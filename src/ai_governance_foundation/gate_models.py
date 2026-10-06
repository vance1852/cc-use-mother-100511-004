"""发布门禁域使用的数据对象。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# 评估批次覆盖的检查族；每次发布决定都要求这些检查在同一候选版本上完成。
REQUIRED_CHECK_FAMILIES = ("vulnerability", "permission", "data_leak")

SEVERITIES = ("critical", "high", "medium", "low")

FINDING_STATUSES = ("open", "mitigated", "reopened")

EVIDENCE_KINDS = ("patch", "retest", "configuration", "documentation")

EXCEPTION_STATUSES = ("active", "revoked", "expired")

# 决定结果。
DECISION_APPROVED = "approved"
DECISION_REJECTED = "rejected"
DECISION_SUPERSEDED = "superseded"
DECISION_INVALIDATED = "invalidated"


@dataclass(frozen=True)
class ReleaseCandidate:
    """发布候选版本：门禁判断的对象。"""

    candidate_id: str
    model_id: str
    version: str
    created_by: str
    created_at: str


@dataclass(frozen=True)
class EvaluationBatch:
    """评估批次：针对某个候选版本某个检查族的一次完整评估。"""

    batch_id: str
    candidate_id: str
    check_family: str
    completed: bool
    version_pin: str
    created_by: str
    created_at: str
    completed_at: str | None


@dataclass(frozen=True)
class Finding:
    """评估发现项，挂在评估批次下；关键发现可被重新打开。"""

    finding_id: str
    batch_id: str
    candidate_id: str
    check_family: str
    severity: str
    title: str
    status: str
    blocking: bool
    created_by: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class RemediationEvidence:
    """修复证据：把一个发现项在某个版本上标记为已缓解。"""

    evidence_id: str
    finding_id: str
    candidate_id: str
    kind: str
    reference: str
    version_pin: str
    created_by: str
    created_at: str


@dataclass(frozen=True)
class ExceptionApproval:
    """例外批准：在有效期内为某个未缓解发现项承担风险。"""

    exception_id: str
    finding_id: str
    candidate_id: str
    approver: str
    reason: str
    expires_at: str
    status: str
    created_by: str
    created_at: str


@dataclass(frozen=True)
class BlockingReason:
    """发布被阻止的一条具体依据及恢复条件。"""

    code: str
    message: str
    recovery: str
    refs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GateEvaluation:
    """对某候选版本当前门禁状态的完整说明。"""

    candidate_id: str
    model_id: str
    version: str
    satisfied: bool
    checked_at: str
    checks: list[dict[str, Any]]
    unresolved_findings: list[dict[str, Any]]
    exceptions: list[dict[str, Any]]
    blocking_reasons: list[BlockingReason]


@dataclass(frozen=True)
class ReleaseDecision:
    """发布决定：不可变历史记录，可能被后续事件废止或被新决定取代。"""

    decision_id: str
    candidate_id: str
    result: str
    basis_candidate_version: str
    basis_digest: str
    rationale: str
    blocking_reasons: list[dict[str, Any]]
    check_summary: dict[str, Any]
    supersedes_decision_id: str | None
    invalidated_by: str | None
    invalidated_reason: str | None
    created_by: str
    created_at: str
    invalidated_at: str | None


@dataclass(frozen=True)
class GateWriteReceipt:
    """描述一次门禁写入的稳定结果。"""

    request_id: str
    resource_type: str
    resource_id: str
    replayed: bool
