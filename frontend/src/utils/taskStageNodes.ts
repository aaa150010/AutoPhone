import type { TaskStageGroup } from '../types/api'

export interface TaskStageNodeDefinition {
  code: string
  label: string
  group: TaskStageGroup
}

// Keep the browser-only entries in one display registry.  The codes mirror
// the stable Camoufox entries registered by the Free runtime; timing data can
// still add a failure node without making the drawer depend on Vue internals.
export const FREE_CAMOUFOX_STAGE_NODES: readonly TaskStageNodeDefinition[] = [
  { code: 'free_camoufox_dependency', label: '检查 Camoufox 依赖', group: 'free' },
  { code: 'free_camoufox_launch', label: '启动 Camoufox 浏览器池', group: 'free' },
  { code: 'free_camoufox_signup', label: 'Camoufox 页面注册', group: 'free' },
  { code: 'free_camoufox_navigation', label: '打开 Camoufox 注册页面', group: 'free' },
  { code: 'free_camoufox_signup_email', label: '填写 Camoufox 注册邮箱', group: 'free' },
  { code: 'free_camoufox_signup_password', label: '提交 Camoufox 注册密码', group: 'free' },
  { code: 'free_camoufox_profile', label: '填写 Camoufox 账号资料', group: 'free' },
  { code: 'free_camoufox_browser', label: 'Camoufox 注册页面', group: 'free' },
  { code: 'free_camoufox_challenge', label: '等待 Camoufox 安全验证', group: 'free' },
]
