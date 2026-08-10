import { ElNotification } from 'element-plus'
import type { AppState, SmsRuntimeAlert } from '../types/api'
import {
  buildConnectivityOutageNotice,
  buildConnectivityRecoveryMessage,
  createConnectivityNotificationTracker,
} from '../utils/openAIConnectivity'
import { createRuntimeAlertTracker, runtimeAlertDuration } from './runtimeAlerts'

export function createRuntimeNotificationObserver() {
  const smsTracker = createRuntimeAlertTracker()
  const connectivityTracker = createConnectivityNotificationTracker()
  let outageNotice: ReturnType<typeof ElNotification> | null = null

  function showSmsAlerts(alerts: SmsRuntimeAlert[]) {
    for (const alert of alerts || []) {
      if (!smsTracker.accept(alert)) continue
      ElNotification({
        title: alert.level === 'error' ? 'SMS 服务异常' : 'SMS 服务提醒',
        message: alert.message,
        type: alert.level || 'warning',
        duration: runtimeAlertDuration(alert),
      })
    }
  }

  function closeOutageNotice() {
    const current = outageNotice
    outageNotice = null
    current?.close()
  }

  return {
    observe(state: AppState) {
      const runtime = state.runtime || {}
      showSmsAlerts(state.sms_alerts || runtime.sms_alerts || [])
      for (const action of connectivityTracker.observe(runtime.connectivity?.openai_auth)) {
        if (action.type === 'close-outage') {
          closeOutageNotice()
          continue
        }
        if (action.type === 'show-recovery') {
          ElNotification({
            title: 'OpenAI 链路已恢复',
            message: buildConnectivityRecoveryMessage(runtime),
            type: 'success',
            duration: 5000,
          })
          continue
        }

        closeOutageNotice()
        const outage = buildConnectivityOutageNotice(runtime)
        const notice = ElNotification({
          ...outage,
          showClose: true,
          onClose: () => {
            if (outageNotice === notice) outageNotice = null
          },
        })
        outageNotice = notice
      }
    },
    dispose() {
      closeOutageNotice()
    },
  }
}
