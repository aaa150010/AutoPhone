export interface ReleaseNoteSection {
  title: string
  usage: string
}

export interface ReleaseNotes {
  version: string
  title: string
  releasedAt: string
  sections: ReleaseNoteSection[]
}

// Keep user-visible release notes here. App components must not embed release copy.
export const currentRelease: ReleaseNotes = {
  version: '1.2.2',
  title: 'SUB2 原账号更新修正',
  releasedAt: '2026-08-11',
  sections: [
    {
      title: '错误定位更具体',
      usage: '启动、配置、预检、任务、邮箱、上传和通知失败会返回明确的中文节点、稳定错误码、已脱敏技术原因和处理建议；取件地址与代理凭据不会出现在错误响应或日志中。',
    },
    {
      title: 'OpenAI 链路诊断',
      usage: '在左侧 OpenAI 状态或运行页异常横幅点击测试按钮。诊断会使用已保存代理检测 auth.openai.com 与 sentinel.openai.com 的延迟；HTTP 429 显示为限流，5xx 显示为服务异常，并避免继续执行 Sentinel 深测。',
    },
    {
      title: '相关故障自动提醒',
      usage: '检测到 Node/Sentinel、OpenAI 授权链路或已确认的 Auth/Sentinel 中断时，诊断框只按当前批次自动打开一次，历史任务不会阻塞或误触发新批次；也可随时手动重新测试。',
    },
    {
      title: '保留 SUB2 当前分组',
      usage: '重登更新已有 SUB2 账号时，只原位更新 OAuth 凭据并保留远端当前分组；手动调整过分组不会再导致更新失败。新建账号仍按运行配置中的目标分组严格校验。',
    },
  ],
}
