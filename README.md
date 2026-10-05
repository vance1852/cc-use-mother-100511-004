# 模型发布安全门禁服务

本项目提供人工智能治理协作的服务端基础能力，用于登记主体、任务、权限、风险事件和结构化证据，并通过角色权限、请求幂等、SQLite 事务与审计链保持业务状态一致。

在此之上，服务实现了**模型发布门禁**：把评估批次、发现项、修复证据、例外批准和发布候选版本关联起来，只有所有必需检查在同一候选版本上完成且例外仍有效时，才能生成批准发布的决定。

## 门禁概念

| 概念 | 说明 |
| --- | --- |
| 发布候选版本 `release_candidates` | 以 `model_name + version` 唯一标识的待发布模型版本 |
| 评估批次 `assessment_batches` | 挂在候选版本上的安全评估，分 `vulnerability`、`permission`、`data_leak` 三类；`open` 可登记发现项，`completed` 表示评估完成 |
| 发现项 `findings` | 批次内的具体问题，严重度 `critical/high/medium/low`，状态 `open/resolved/reopened` |
| 修复证据 `fix_evidences` | 关闭发现项时必须一并提交的修复说明与工件地址 |
| 例外批准 `exception_approvals` | 仅管理员可签发，带 `valid_until` 有效期，可撤销 |
| 发布决定 `release_decisions` | 只追加不修改；`approved` 或 `blocked`，阻断时逐项记录依据与恢复条件 |
| 决定失效 `release_decision_invalidations` | 失效是追加的记录，历史决定保持原样 |

## 门禁规则

1. 三类必需检查（漏洞、权限、数据泄露）必须在**同一候选版本**上各有一个已完成的评估批次；其他版本上的评估结果不计入。每类检查以最近提交的已完成批次为管辖评估。
2. 管辖批次内的每个发现项必须已关闭（提交修复证据），或拥有仍在有效期内且未撤销的例外批准。
3. 满足以上条件时生成的决定为 `approved`，否则为 `blocked` 并逐项给出 `code`、`message` 和 `recovery`。
4. 关键发现（`critical`）被重新打开时，该候选版本所有仍有效的批准决定在同一事务内被登记失效；例外被撤销或过期同样使依赖它的批准失效（过期由读取与决定路径惰性扫描登记）。失效单向追加，旧决定不被覆盖。
5. 所有写路径在 `BEGIN IMMEDIATE` 事务内完成校验、写入、失效登记与审计追加，事务在进程内互斥执行；每个写接口按 `request_id` 幂等。并发提交与服务重启不会产生两个互相矛盾的决定，重启后用同一 `request_id` 重试只会回放首次结果。

## HTTP 接口

写接口（`POST`，请求体均含 `request_id`，调用方身份经 `X-Actor-Id` 头传递）：

- `/release-candidates`：登记候选版本（admin/operator）
- `/assessment-batches`：提交评估批次（admin/reviewer）
- `/assessment-batch-completions`：完成评估批次（admin/reviewer）
- `/findings`：在开放批次内登记发现项（admin/reviewer）
- `/finding-resolutions`：提交修复证据并关闭发现项（admin/reviewer）
- `/finding-reopens`：重新打开已关闭的发现项（admin/reviewer）
- `/exception-approvals`：签发例外批准（admin）
- `/exception-revocations`：撤销例外批准（admin）
- `/release-decisions`：生成发布决定（admin/operator），返回决定全文与阻断依据

查询接口（`GET`）：

- `/release-gate/status?candidate_id=`：实时评估是否可发布及恢复条件
- `/release-decisions/current?candidate_id=`：最近决定、当前有效性、失效原因与当前阻断项
- `/release-decisions?candidate_id=`：完整决定历史（含失效记录）
- `/release-candidates`、`/assessment-batches?candidate_id=`、`/findings?candidate_id=`

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
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务提供健康检查和带操作者身份的业务请求，重启后 SQLite 中的状态、发布决定历史与审计链继续保留。
