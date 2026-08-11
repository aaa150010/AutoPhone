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
  version: '1.1.0',
  title: '历史成本、原格式导出与邮箱分割器',
  releasedAt: '2026-08-11',
  sections: [
    {
      title: '全部接码均成本',
      usage: '运行中心顶部新增历史均成本卡，展示全部历史计费账号数、总金额和每号平均成本。',
    },
    {
      title: '按原始格式导出邮箱',
      usage: '在邮箱管理勾选邮箱，打开“上传与导出”，点击“导出原始格式”，确认后下载 TXT。文件会保留导入时的字段、分隔符、大小写和顺序。',
    },
    {
      title: '邮箱分割器',
      usage: '打开左侧“邮箱分割”，粘贴原始数据并填写切出数量。右侧得到前 N 条，左侧保留剩余数据，可分别复制或下载 TXT。数据仅保存在当前页面会话内存中。',
    },
    {
      title: '新版本首次使用说明',
      usage: '以后每个新版本第一次打开都会显示本说明；确认后，同一浏览器在该版本内不再重复弹出。',
    },
  ],
}
