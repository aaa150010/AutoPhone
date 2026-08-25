# AGENTS.md

## 项目范围

GPT 注册中心（gptPhone）是 macOS 本地 Flask + Vue 3/Element Plus 应用，包含普通短信/OAuth 流程和 Free 注册流程。恢复的后端模块是 Python 3.13 运行时产物；可维护的后端改动放在 `mac_overrides/`，不要把 `business_pyc/`、`plus_launcher.pyc` 或 `pycdc_attempt/` 当作源码重构。

## 最高优先级：照抄 AutoRegister

Free 全协议链路和 RoxyBrowser 链路必须以同级项目 `/Users/lwh/projects/AutoRegister` 为行为基准，整体照抄其真实实现和调用顺序：会话建立、网络预检、匿名预热、OAuth/登录页面状态机、Sentinel、代理池分配、邮箱提交后的分支、OTP 页面、资料页、consent、OAuth 回调、Session 刷新、2FA、结果持久化、失败清理、Profile 生命周期、`connection_info` 对账和结构化诊断都按 AutoRegister 的逻辑实现。代理来自池并按任务上下文传递，但不得强制“一号一 IP”或因出口 IP 轮换拒绝健康任务。

唯一允许保留 AutoPhone 自己实现的是邮箱解析和邮箱验证码获取：继续使用 `mac_overrides/mailbox_otp_service.py` 及其现有策略模式，包括来源解析、请求前基线、旧验证码排除、消息身份判断、时间过滤、轮询、重发和阶段隔离。除这些邮箱取件边界外，不得自行设计另一套注册链路，不得为了兼容旧实现而保留与 AutoRegister 不同的主流程。

对照位置：

- 协议注册：`/Users/lwh/projects/AutoRegister/core/chatgpt_auth.py`、`core/openai_auth.py`、`core/sentinel_runner.py`、`main.py`。
- RoxyBrowser：`core/roxy_registration.py`、`core/roxybrowser_client.py`、`core/otp_utils.py`、`core/humanize.py`、`core/live_check_service.py`、`config/proxy.py`、`config/roxybrowser.py`。
- 只吸收实现逻辑，不复制任何账号、邮箱密码、Cookie、Token、验证码、代理凭据、运行数据或第三方授权信息。
- 开源参考副本仅作只读对照；新建的临时副本使用完必须删除。项目保留的长期只读副本除非用户明确要求，不得删除。

## 编辑边界和数据隔离

- 后端行为改动放在 `mac_overrides/`，`mac_overrides/web_gui.py` 负责加载恢复模块和应用定向覆盖。
- 普通短信/OAuth 与 Free 注册的数据必须隔离。Free 配置、邮箱/代理池、任务、日志、锁和结果放在 `${GPTPHONE_DATA_DIR}/free_register/`，普通流程不得读取、聚合、修改或消耗这些状态。
- 支付链接工具只使用 `${GPTPHONE_DATA_DIR}/payment_tools/`，网络诊断只使用 `${GPTPHONE_DATA_DIR}/network_tools/`，不得复用注册任务状态。
- 前端源代码放在 `frontend/src/`；`frontend/dist/` 已纳入版本控制，前端源代码有变化时必须重新构建并更新产物。
- 不要提交 `data/`、`mac_runtime/`、`engine/`、`node_chain.dat`、`frontend/node_modules/`、缓存、导出文件或秘密。

## 安全和诊断

- 未经用户明确同意，不得使用 `computer-use`、应用内浏览器、Chrome、Playwright 或真实浏览器操作。
- 不得在日志、公共 API、任务结果或持久化记录中暴露邮箱密码、代理凭据、Cookie、OAuth URL 查询参数、授权头、access/refresh/ID/admin token、短信/邮箱验证码、手机号或 TOTP 秘密；公共状态只能使用掩码或短指纹。
- 每个失败必须保留稳定节点代码、中文节点名称、HTTP 状态/服务商代码（如有）和脱敏的可操作原因；不能用“操作失败”或“failed”覆盖首个真实节点。
- Cloudflare、人机验证和安全挑战只记录并停止，禁止自动绕过。Session 失效、网络临时错误和业务限流必须按 AutoRegister 的重试边界处理；不得把业务 429 当成可重复提交信号。
- 代理测试必须使用所选代理声明的协议，清除继承的 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`，不得静默切换节点或回退到 Clash。当前主机 Clash Verge HTTP 代理是 `http://127.0.0.1:7897`；`12334` 不是有效配置，出现时必须追溯来源并修复。
- 测试和诊断不得覆盖用户运行数据；需要临时数据目录时使用临时目录，任务结束后删除由本次任务创建的临时副本。

## 兼容和实现要求

- 覆盖恢复模块前先保存原方法，保持原有可调用签名（包括 keyword-only 参数），只做窄范围覆盖。
- 对不确定的恢复方法先查 `disassembly/index.json` 的对应切片，并在 Python 3.13 环境用 `inspect.signature` 确认签名。
- 保留已有配置字段和页面顺序，除非用户明确要求删除或调整。
- OTP 的请求基线、旧码排除和阶段状态必须按注册、已有账号登录、2FA enrollment 分开；取消、重试、清理不得覆盖原始终止原因。
- 真实邮箱注册或真实代理动作不是普通静态验证的一部分；只有用户明确授权时才可执行，且不得把失败的真实尝试伪装成成功。

## 发布和验证

- 用户可见的版本说明统一写在 `frontend/src/releaseNotes.ts`；涉及用户可见改动时同步更新版本号和说明，并重建 `frontend/dist/`。
- 后端验证：

  ```sh
  mac_runtime/.venv/bin/python -m unittest discover -s tests -v
  mac_runtime/.venv/bin/python -m py_compile mac_overrides/error_observability.py mac_overrides/web_gui.py mac_overrides/sms_runtime.py mac_overrides/task_progress.py
  ```

- 前端验证：

  ```sh
  cd frontend
  npx vue-tsc --noEmit
  npm run build
  ```

- 最后运行 `git diff --check`。除非用户明确要求，不要启动或重启 Flask 服务，也不要点击真实注册、短信、SUB2、Pixel、支付提取或代理测试动作。
