# `mac_overrides/` 维护约束

## Free 日志与诊断

- Free 新日志必须通过 `diagnostic_writer.DiagnosticEventWriter` 写入
  `DiagnosticStore`；禁止在业务模块中直接拼接私有日志格式或直接写诊断
  SQLite 表。
- `LogContext` 是任务、批次、链路、driver、阶段和 attempt 的唯一上下文
  入口。新增字段先加入白名单和对应测试，再接入调用方。
- 日志只允许保存脱敏文本、稳定节点代码、事件/incident 标识和 HMAC
  指纹。邮箱原文、取件 URL 查询参数、密码、Token、Cookie、验证码、
  TOTP Secret、手机号和代理凭据不得进入事件、兼容响应或调试 artifact。
- `FreeLogStore` 是兼容 facade。新运行时应使用
  `legacy_projection=False`，从 `DiagnosticStore` 读取事件；旧
  `logs.json`/`task_logs/*.json` 只能由 `free_log_migration` 一次性清理，
  不得重新作为事实来源。
- 诊断写入失败不得改变业务结果；必须保留 `DiagnosticStore.health()`
  的 degraded 计数，并把清理/存储错误作为关联事件记录。

## 变更与验证

- 先为新诊断字段、清理行为和兼容 facade 添加 focused tests，再修改业务
  代码；失败排查以首个真实节点为准。
- 日志模块只负责事件投影、脱敏和兼容读取，不得承担任务调度、邮箱取码、
  代理分配或 Camoufox 状态机逻辑。
- 临时诊断目录和测试数据必须在测试结束时删除；禁止使用真实邮箱、代理、
  浏览器或 computer-use 做静态验证。
