"""提供不依赖第三方框架的 HTTP/JSON 边界。"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError
from .release_gate import ReleaseGateService
from .service import DomainService
from .storage import Database


def _created_or_replayed(result: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    return (200 if result.get("replayed") else 201), result


def _required_query(parsed, name: str) -> str:
    value = parse_qs(parsed.query).get(name, [""])[0]
    if not value:
        raise ValidationError(f"{name} 不能为空")
    return value


def route(service: DomainService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    """把一个 HTTP 语义请求分派到领域服务。"""

    headers = headers or {}
    body = body or {}
    parsed = urlparse(path)
    actor_id = headers.get("X-Actor-Id", "")
    try:
        if method == "GET" and parsed.path == "/health":
            valid, count = service.verify_audit()
            return 200, {"status": "ok", "audit_valid": valid, "audit_events": count}
        if method == "POST" and parsed.path == "/organizations":
            receipt = service.register_organization(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/actors":
            receipt = service.register_actor(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/sites":
            receipt = service.register_site(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/domain-records":
            receipt = service.record_domain_data(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/domain-records":
            query = parse_qs(parsed.query)
            site_id = query.get("site_id", [""])[0]
            if not site_id:
                raise ValidationError("site_id 不能为空")
            category = query.get("category", [None])[0]
            return 200, {"items": [item.__dict__ for item in service.list_domain_data(site_id, category)]}
        if method == "GET" and parsed.path == "/audit-events":
            query = parse_qs(parsed.query)
            after = int(query.get("after_sequence", ["0"])[0])
            return 200, {"items": service.audit_events(after)}
        if method == "POST" and parsed.path == "/release-candidates":
            return _created_or_replayed(service.register_candidate(actor_id=actor_id, **body))
        if method == "GET" and parsed.path == "/release-candidates":
            query = parse_qs(parsed.query)
            model_name = query.get("model_name", [None])[0]
            return 200, {"items": service.list_candidates(model_name)}
        if method == "POST" and parsed.path == "/assessment-batches":
            return _created_or_replayed(service.submit_batch(actor_id=actor_id, **body))
        if method == "GET" and parsed.path == "/assessment-batches":
            candidate_id = _required_query(parsed, "candidate_id")
            return 200, {"items": service.list_batches(candidate_id)}
        if method == "POST" and parsed.path == "/assessment-batch-completions":
            return _created_or_replayed(service.complete_batch(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/findings":
            return _created_or_replayed(service.add_finding(actor_id=actor_id, **body))
        if method == "GET" and parsed.path == "/findings":
            candidate_id = _required_query(parsed, "candidate_id")
            return 200, {"items": service.list_findings(candidate_id)}
        if method == "POST" and parsed.path == "/finding-resolutions":
            return _created_or_replayed(service.resolve_finding(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/finding-reopens":
            return _created_or_replayed(service.reopen_finding(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/exception-approvals":
            return _created_or_replayed(service.approve_exception(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/exception-revocations":
            return _created_or_replayed(service.revoke_exception(actor_id=actor_id, **body))
        if method == "POST" and parsed.path == "/release-decisions":
            return _created_or_replayed(service.generate_decision(actor_id=actor_id, **body))
        if method == "GET" and parsed.path == "/release-decisions":
            candidate_id = _required_query(parsed, "candidate_id")
            return 200, {"items": service.list_decisions(candidate_id)}
        if method == "GET" and parsed.path == "/release-decisions/current":
            candidate_id = _required_query(parsed, "candidate_id")
            return 200, service.current_decision(candidate_id)
        if method == "GET" and parsed.path == "/release-gate/status":
            candidate_id = _required_query(parsed, "candidate_id")
            return 200, service.gate_status(candidate_id)
        return 404, {"error": "route_not_found", "message": "接口不存在"}
    except DomainError as exc:
        return exc.status, {"error": exc.code, "message": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


class Handler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为路由调用。"""

    service: DomainService

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid_json", "message": "请求体必须是 UTF-8 JSON"})
            return
        status, payload = route(self.service, self.command, self.path, body,
                                {"X-Actor-Id": self.headers.get("X-Actor-Id", "")})
        self._write(status, payload)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    """启动本地 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动人工智能治理与模型发布门禁服务")
    parser.add_argument("--database", default="service.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    Handler.service = ReleaseGateService(database)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
