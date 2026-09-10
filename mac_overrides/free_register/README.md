# Free 注册编排边界（free_register）

本包是 Free 注册任务编排的迁移边界。历史入口
[`free_register_runtime.py`](../free_register_runtime.py) 仍是兼容 facade：
`FreeRegisterManager` 通过多个 `*Mixin` 组合（进程所有权、失败投影、调度、
预检、启动、重试、协议、计时、投影），新代码应优先依赖本包的边界而不是
facade 的私有 helper。

| 模块 | 职责 | 不得包含 |
| --- | --- | --- |
| `contracts.py` | 无依赖的任务/租约/结果数据类契约 | I/O、浏览器、密钥 |
| `task_repository.py` | 基于 Free SQLite 的修订号（revision）任务与邮箱租约仓储 | 业务状态决策、重试分类 |
| `retry_policy.py` | 统一重试分类（`_BLOCKED_HTTP_STATUSES` / `_BLOCKED_MARKERS` / `_PRE_SUBMISSION_NODES`） | 存储、浏览器操作 |
| `mailbox_lease.py` | 两阶段邮箱租约协调（acquire → confirm / abort） | 任务状态机、诊断写入 |
| `worker.py` | 与传输无关的 worker 组合 | provider/驱动细节 |
| `timing.py` | 有界任务计时记录 | 传输实现 |
| `manager.py` | 兼容 manager 的组合根（`build_manager_components`） | 新业务规则 |

相关但位于本包之外的编排模块：`free_register_owner.py`（进程所有权 fence）、
`free_register_startup.py` / `free_register_retry.py`（mixin 实现体）、
`free_register_config.py`（配置单源）。

## 约定

- 新节点登记五表 + 前端回退表的完整清单见
  [`docs/ADD_A_FEATURE.md`](../../docs/ADD_A_FEATURE.md) 第 1 节。
- 邮箱取件一律复用 `mailbox_otp_service.py` 策略，本包不得另造 provider
  （AGENTS.md 3.4）。
- 任务持久化只走 `free_storage.py`/适配器提供的独立 SQLite，不与普通
  SMS/OAuth 数据共享（AGENTS.md 3.1/4）。
- 涉及租约回调的改动（confirm 闭包、续跑剥除继承回调）必须先跑
  `tests/test_free_mailbox_lease*.py` 聚焦测试再全量。
