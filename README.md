# 模型发布安全门禁服务

本项目在人工智能治理基础能力（主体、场所、资料登记、角色权限、请求幂等、SQLite
事务与哈希链审计）之上，提供**模型发布门禁（Release Gate）**：把评估批次、发现项、
修复证据、例外批准与发布候选版本关联起来，只有当所有必需检查在**同一候选版本**上
完成、所有阻断级发现项在同一版本上缓解（或持有仍有效的例外批准）时，才能生成
"可发布"决定。

## 门禁规则

1. 三个必需检查族 `vulnerability`（漏洞）、`permission`（权限）、`data_leak`
   （数据泄露）的最新评估批次必须完成，且批次的 `version_pin` 必须与候选版本
   完全一致；登记批次时版本不符会被直接拒绝。
2. `critical`/`high` 发现项为阻断级。阻断解除只有两条路：
   - 提交**固定在候选版本**上的修复/复测证据（其他版本证据只保留记录，不解除阻断）；
   - 持有管理员批准、未撤销且未到期的例外（发现项被重新打开后，旧例外失效，
     必须就重开事实重新批准）。
3. 发生下列任一事件时，当前生效的"批准"决定在**同一事务内立即失效**，历史决定行
   原样保留（结果仍是 approved，状态标记为 invalidated），绝不覆盖：
   关键发现项被重新打开、例外被撤销或到期、出现新一轮未完成评估、出现新的阻断级发现项。
4. 决定只在单个 `BEGIN IMMEDIATE` 事务内依据状态快照生成；状态依据（`basis_digest`）
   未变时复用同一条生效决定。数据库层还有"每候选版本至多一条生效决定"的部分唯一索引，
   因此并发提交与进程重启都不会产生两条互相矛盾的生效决定。
5. `GET /gate-status` 完整说明某次发布被阻止的**具体依据**（`blocking_reasons`，
   含 code、涉及对象、所需版本）和**恢复条件**（`recovery`），并返回当前生效决定、
   最近失效决定及失效原因。

## 主要接口

| 方法 | 路径 | 说明 | 所需角色 |
| --- | --- | --- | --- |
| POST | `/release-candidates` | 登记发布候选版本（模型+版本唯一） | admin/operator |
| POST | `/evaluation-batches` | 在候选版本上登记评估批次（必须固定版本） | admin/reviewer |
| POST | `/evaluation-batches/complete` | 完成评估批次 | admin/reviewer |
| POST | `/findings` | 登记发现项（critical/high 自动标记阻断） | admin/reviewer |
| POST | `/findings/reopen` | 重新打开发现项（关键项使旧批准失效） | admin/reviewer |
| POST | `/remediation-evidence` | 提交修复证据（版本必须与候选一致才解除阻断） | admin/operator/reviewer |
| POST | `/exceptions` | 批准例外（含到期时间） | admin |
| POST | `/exceptions/revoke` | 撤销例外（使旧批准失效） | admin |
| POST | `/release-decisions` | 依据当前快照生成发布决定 | admin |
| GET | `/release-decisions?candidate_id=…` / `?decision_id=…` | 决定历史（不覆盖）/单条决定 | 任意 |
| GET | `/gate-status?candidate_id=…` | 阻断依据、恢复条件、生效/失效决定 | 任意 |
| GET | `/findings`、`/exceptions` | 发现项/例外列表 | 任意 |

所有写接口都要求 `X-Actor-Id` 头和唯一 `request_id`（重复请求幂等回放，
同号不同内容返回 409）。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
# 基础治理链
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance
# 发布门禁完整决策链（阻止→证据版本不符→批准→重开失效→重新批准→例外到期）
PYTHONPATH=src python3 -m ai_governance_foundation.gate_acceptance
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务提供健康检查和带操作者身份的业务请求，重启后 SQLite 中的门禁状态、决定历史
与审计链继续保留。
