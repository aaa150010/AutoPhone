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
  version: '1.3.4',
  title: '邮箱列表提速与停用空间即时清理',
  releasedAt: '2026-08-12',
  sections: [
    {
      title: '优先查看待处理任务',
      usage: '任务结果分为待处理、运行中和全部。首次出现验证码或失败任务时自动进入待处理；验证码提交后立即移出，新一代验证码会重新进入，成功和主动停止仅在全部中查看。',
    },
    {
      title: '任务行快捷处理邮箱',
      usage: '待处理表中点击邮箱即可复制；密码按需读取后复制，2FA 按需生成临时验证码并复制，取件 URL 在新页面打开。源邮箱行、明文密码、2FA 密钥和 URL 不会随任务列表返回。',
    },
    {
      title: '更紧凑的凭据操作列',
      usage: '任务表邮箱列缩窄约三成，密码和 2FA 改为图标操作；顶部使用紧凑分段页签，不再铺满整张表，存在待处理任务时仅用红色文字和数量徽标提醒。悬浮图标可查看用途，点击行为仍分别为复制密码和生成并复制临时验证码。',
    },
    {
      title: '自动清理已停用空间邮箱',
      usage: '查询 OpenAI 额度或执行本机 OpenAI 批量测试时，仅当接口同时返回 HTTP 402 且 detail.code 精确为 deactivated_workspace，才立即删除对应的本地邮箱，无需等待同一分块或整批结束。其他 402、401、403、404、429、服务异常和网络错误均不会删除，SUB2 账号不受影响。',
    },
    {
      title: '大邮箱池增量加载',
      usage: '邮箱管理会复用未变化的结果、额度和风控文件，只增量加载发生变化的内容，较大的邮箱池刷新更快，运行进度仍会实时更新。遇到缓存扫描异常时会自动暂时回退；也可在运行设置关闭邮箱结果增量索引，恢复完整扫描。',
    },
    {
      title: '验证码提交后立即移出',
      usage: '验证码提交成功后，该任务立即离开待处理并继续运行；同一任务出现新一代验证码请求时会重新进入待处理。待处理清空后自动返回运行中。',
    },
    {
      title: '运行中稳定追加邮箱',
      usage: '批次运行时可导入任意数量的有效邮箱。任务状态、批次清单和队列完整确认后才执行，并沿用配置并发，不受批次开始时邮箱数量限制。',
    },
    {
      title: '重登与导入竞态隔离',
      usage: '重登运行期间导入的新邮箱会进入下一批注册优先队列，不会误入重登链路；邮箱写入期间批次刚好启动或结束时也会重新确认归属。',
    },
  ],
}
