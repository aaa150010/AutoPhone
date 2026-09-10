<script setup lang="ts">
import { computed, ref } from 'vue'
import type { AppConfigForm } from '../utils/appConfigNormalize'
import FieldHelpLabel from './FieldHelpLabel.vue'
import { ArrowDown, ArrowUp } from '@element-plus/icons-vue'

const props = defineProps<{ modelValue: AppConfigForm }>()
const emit = defineEmits<{ 'update:modelValue': [AppConfigForm] }>()

const showAdvanced = ref(false)

function update(key: string, value: unknown) {
  emit('update:modelValue', { ...props.modelValue, [key]: value })
}

function updateProxyScope(key: string, value: boolean | string | number) {
  emit('update:modelValue', {
    ...props.modelValue,
    proxy_scope: {
      ...(props.modelValue.proxy_scope || {}),
      [key]: Boolean(value),
    },
  })
}

/** Advanced controls collapse by default; the proxy block and connectivity
 * guard stay visible because operators consult them most often. */
const advancedActive = computed(() => (
  props.modelValue.task_inflight_optimization === false
  || props.modelValue.phone_binding_compatibility === false
  || props.modelValue.mailbox_result_index_cache === false
))
</script>

<template>
  <div class="settings-section">
    <h2 class="section-title">基础运行配置</h2>
    <p class="section-hint">接码机批次的代理、并发与保护策略；修改后使用右上角"保存配置"生效。</p>

    <section class="settings-card">
      <h3 class="card-title">代理配置</h3>
      <el-row :gutter="12">
        <el-col :span="12">
          <el-form-item>
            <template #label><FieldHelpLabel label="代理地址" help="接码 / OAuth / SUB2 共用的本机代理；留空表示直连。继承的系统代理环境变量会被清除。" /></template>
            <el-input
              :model-value="modelValue.proxy"
              placeholder="http://127.0.0.1:7897"
              @update:model-value="update('proxy', $event)" size="small" />
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item>
            <template #label><FieldHelpLabel label="代理生效范围" help="分别控制 SMS、邮箱取码和 SUB2 上传是否经过上面的代理。" /></template>
            <div class="scope-row">
              <el-checkbox
                :model-value="Boolean(modelValue.proxy_scope?.sms)"
                @update:model-value="updateProxyScope('sms', $event)"
              >SMS 走代理</el-checkbox>
              <el-checkbox
                :model-value="Boolean(modelValue.proxy_scope?.email)"
                @update:model-value="updateProxyScope('email', $event)"
              >邮箱取码走代理</el-checkbox>
              <el-checkbox
                :model-value="Boolean(modelValue.proxy_scope?.upload)"
                @update:model-value="updateProxyScope('upload', $event)"
              >SUB2 走代理</el-checkbox>
            </div>
          </el-form-item>
        </el-col>
      </el-row>
    </section>

    <section class="settings-card">
      <h3 class="card-title">并发与超时</h3>
      <el-row :gutter="12">
        <el-col :span="8">
          <el-form-item>
            <template #label><FieldHelpLabel label="目标数量（个）" help="本批次要注册的账号总数。" /></template>
            <el-input-number
              :model-value="Number(modelValue.target_count || 1)"
              :min="1"
              :max="10000"
              controls-position="right"
              @update:model-value="update('target_count', String($event ?? 1))" size="small" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item>
            <template #label><FieldHelpLabel label="并发数（个）" help="同时运行的注册任务数；实际并发可能因链路保护自动降低。" /></template>
            <el-input-number
              :model-value="Number(modelValue.concurrency || 5)"
              :min="1"
              :max="8"
              controls-position="right"
              @update:model-value="update('concurrency', String($event ?? 5))" size="small" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item>
            <template #label><FieldHelpLabel label="Node 并发数（个）" help="Sentinel / Node 执行器的并发上限。" /></template>
            <el-input-number
              :model-value="Number(modelValue.node_concurrency || 5)"
              :min="1"
              :max="100"
              controls-position="right"
              @update:model-value="update('node_concurrency', String($event ?? 5))" size="small" />
          </el-form-item>
        </el-col>
      </el-row>
      <el-row :gutter="12">
        <el-col :span="8">
          <el-form-item>
            <template #label><FieldHelpLabel label="Node 超时（秒）" help="单个 Node/Sentinel 步骤的最长等待时间。" /></template>
            <el-input-number
              :model-value="Number(modelValue.node_timeout ?? 45)"
              :min="1"
              :max="3600"
              controls-position="right"
              @update:model-value="update('node_timeout', Number($event ?? 45))" size="small" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item>
            <template #label><FieldHelpLabel label="邮箱验证码超时（秒）" help="等待邮箱验证码的最长时间；超时后任务按可重试失败处理。" /></template>
            <el-input-number
              :model-value="Number(modelValue.email_code_timeout ?? 60)"
              :min="30"
              :max="600"
              controls-position="right"
              @update:model-value="update('email_code_timeout', Number($event ?? 60))" size="small" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item>
            <template #label><FieldHelpLabel label="鉴权额外重试（次）" help="鉴权会话建立失败时的额外尝试次数。" /></template>
            <el-input-number
              :model-value="Number(modelValue.auth_session_retries ?? 1)"
              :min="0"
              :max="4"
              controls-position="right"
              @update:model-value="update('auth_session_retries', Number($event ?? 1))" size="small" />
          </el-form-item>
        </el-col>
      </el-row>
      <el-row :gutter="12">
        <el-col :span="8">
          <el-form-item>
            <template #label><FieldHelpLabel label="邮箱登录并发（个）" help="批量邮箱登录动作的并发上限，不超过主并发数。" /></template>
            <el-input-number
              :model-value="Number(modelValue.auto_email_login_concurrency ?? 5)"
              :min="1"
              :max="Math.max(1, Number(modelValue.concurrency || 5))"
              controls-position="right"
              @update:model-value="update('auto_email_login_concurrency', Number($event ?? 5))" size="small" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item>
            <template #label><FieldHelpLabel label="手机提交并发（个）" help="手机号提交阶段的并发上限。" /></template>
            <el-input-number
              :model-value="Number(modelValue.phone_submission_concurrency ?? 2)"
              :min="1"
              :max="5"
              controls-position="right"
              @update:model-value="update('phone_submission_concurrency', Number($event ?? 2))" size="small" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item>
            <template #label><FieldHelpLabel label="协议健康并发上限（个）" help="协议链路健康检查允许的最大并发；链路异常时自动回落。" /></template>
            <el-input-number
              :model-value="Number(modelValue.protocol_concurrency_ceiling ?? 12)"
              :min="8"
              :max="15"
              controls-position="right"
              @update:model-value="update('protocol_concurrency_ceiling', Number($event ?? 12))" size="small" />
          </el-form-item>
        </el-col>
      </el-row>
    </section>

    <section class="settings-card">
      <h3 class="card-title">链路保护</h3>
      <p class="card-hint">OpenAI 链路保护在请求连续失败时暂停新任务；任务规模优化控制同时在途的任务量。</p>
      <div class="switch-grid">
        <div class="switch-item">
          <div class="switch-copy">
            <span class="switch-label">OpenAI 链路保护</span>
            <span class="switch-help">失败退避期间暂停派发新任务</span>
          </div>
          <el-switch
            :model-value="modelValue.openai_connectivity_guard !== false"
            active-text="启用"
            inactive-text="关闭"
            @update:model-value="update('openai_connectivity_guard', Boolean($event))"
          />
        </div>
        <div class="switch-item">
          <div class="switch-copy">
            <span class="switch-label">保守自适应任务并发</span>
            <span class="switch-help">按链路健康自动收紧并发</span>
          </div>
          <el-switch
            :model-value="modelValue.adaptive_task_concurrency !== false"
            active-text="启用"
            inactive-text="关闭"
            @update:model-value="update('adaptive_task_concurrency', Boolean($event))"
          />
        </div>
      </div>
    </section>

    <section class="settings-card">
      <div class="card-title-row">
        <div>
          <h3 class="card-title">任务与兼容优化</h3>
          <p class="card-hint">在途任务上限、手机号绑定兼容与结果索引缓存；默认值适合绝大多数场景。</p>
        </div>
        <el-button
          size="small"
          text
          :icon="showAdvanced ? ArrowUp : ArrowDown"
          :type="advancedActive && !showAdvanced ? 'warning' : undefined"
          @click="showAdvanced = !showAdvanced"
        >{{ showAdvanced ? '收起高级配置' : '显示高级配置' }}</el-button>
      </div>
      <el-collapse-transition>
        <div v-show="showAdvanced">
          <el-row :gutter="12">
            <el-col :span="12">
              <el-form-item>
                <template #label><FieldHelpLabel label="20 条在途任务优化" help="限制同时在途的任务数，避免任务堆积拖垮链路。" /></template>
                <el-switch
                  :model-value="modelValue.task_inflight_optimization !== false"
                  active-text="启用"
                  inactive-text="关闭"
                  @update:model-value="update('task_inflight_optimization', Boolean($event))"
                />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item>
                <template #label><FieldHelpLabel label="在途任务上限（个）" help="关闭上方优化后此值不生效。" /></template>
                <el-input-number
                  :model-value="Number(modelValue.task_inflight_limit ?? 20)"
                  :min="1"
                  :max="20"
                  controls-position="right"
                  :disabled="modelValue.task_inflight_optimization === false"
                  @update:model-value="update('task_inflight_limit', Number($event ?? 20))" size="small" />
              </el-form-item>
            </el-col>
          </el-row>
          <div class="switch-grid">
            <div class="switch-item">
              <div class="switch-copy">
                <span class="switch-label">手机号绑定兼容</span>
                <span class="switch-help">兼容旧号段提交入口</span>
              </div>
              <el-switch
                :model-value="modelValue.phone_binding_compatibility !== false"
                active-text="启用"
                inactive-text="关闭"
                @update:model-value="update('phone_binding_compatibility', Boolean($event))"
              />
            </div>
            <div class="switch-item">
              <div class="switch-copy">
                <span class="switch-label">邮箱结果增量索引</span>
                <span class="switch-help">缓存结果文件索引，降低轮询开销</span>
              </div>
              <el-switch
                :model-value="modelValue.mailbox_result_index_cache !== false"
                active-text="启用"
                inactive-text="关闭"
                @update:model-value="update('mailbox_result_index_cache', Boolean($event))"
              />
            </div>
          </div>
        </div>
      </el-collapse-transition>
      <p v-if="advancedActive && !showAdvanced" class="card-hint customized">有高级配置与默认值不同，展开可查看</p>
    </section>
  </div>
</template>

<style scoped>
.section-title { margin: 0 0 3px; font-size: 14px; line-height: 20px; font-weight: 680; letter-spacing: 0; }
.section-hint, .card-hint { margin: 0 0 10px; color: var(--el-text-color-secondary); font-size: 12px; line-height: 18px; }
.card-hint.customized { margin: 2px 0 0; color: var(--el-color-warning); }
.settings-card { margin-bottom: 14px; padding: 12px 14px 2px; border: 1px solid var(--workspace-border); border-radius: var(--workspace-radius); background: var(--workspace-surface); }
.settings-card:last-child { margin-bottom: 0; }
.card-title { margin: 0 0 10px; font-size: 13px; line-height: 18px; font-weight: 680; }
.card-title-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
.card-title-row .card-title { margin-bottom: 2px; }
.card-title-row .card-hint { margin-bottom: 8px; }
.settings-section :deep(.el-input-number) { width: 100%; }
.scope-row { display: flex; flex-wrap: wrap; gap: 2px 14px; min-height: 30px; align-items: center; }
.scope-row :deep(.el-checkbox) { margin-right: 0; }
.switch-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 16px; padding-bottom: 12px; }
.switch-item { display: flex; align-items: center; justify-content: space-between; gap: 10px; min-height: 40px; padding: 4px 10px; border: 1px solid var(--workspace-border); border-radius: 6px; background: var(--workspace-subtle); }
.switch-copy { display: grid; gap: 1px; min-width: 0; }
.switch-label { overflow: hidden; color: var(--el-text-color-primary); font-size: 12px; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.switch-help { overflow: hidden; color: var(--el-text-color-secondary); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
</style>
