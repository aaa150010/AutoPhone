<script setup lang="ts">
import { computed } from 'vue'
import { Coin, Setting } from '@element-plus/icons-vue'
import SmsApiKeyEditor from './SmsApiKeyEditor.vue'
import type { SmsKeyStatus, SmsProviderPool } from '../types/api'

const props = defineProps<{ modelValue: any; statuses?: SmsKeyStatus[]; queryingBalances?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [any]; queryBalances: [] }>()

function update(key: string, value: any) {
  emit('update:modelValue', { ...props.modelValue, [key]: value })
}

const platformDefaults: Array<SmsProviderPool & { label: string }> = [
  { provider: 'smsbower', label: 'SMSBower', enabled: true, api_keys: [''], service: 'dr' },
  { provider: 'herosms', label: 'HeroSMS', enabled: true, api_keys: [''], service: 'dr' },
  { provider: '5sim', label: '5SIM', enabled: true, api_keys: [''], service: 'openai' },
]

const providerPools = computed(() => {
  const rows = Array.isArray(props.modelValue.sms_provider_pools)
    ? props.modelValue.sms_provider_pools
    : []
  const legacyKeys = Array.isArray(props.modelValue.sms_api_keys)
    ? props.modelValue.sms_api_keys
    : [props.modelValue.sms_api_key || '']
  const byProvider = new Map(rows.map((row: any) => [String(row?.provider || '').toLowerCase(), row]))
  const known = platformDefaults.map((defaults) => {
    const row: any = byProvider.get(defaults.provider)
    const keys = Array.isArray(row?.api_keys)
      ? row.api_keys
      : defaults.provider === 'smsbower' && !rows.length
        ? legacyKeys
        : defaults.api_keys
    return {
      ...defaults,
      ...(row || {}),
      enabled: row?.enabled !== false,
      api_keys: keys.length ? keys : [''],
      service: String(row?.service || defaults.service),
    }
  })
  const extras = rows
    .filter((row: any) => row?.provider && !platformDefaults.some(item => item.provider === row.provider))
    .map((row: any) => ({
      provider: String(row.provider),
      label: String(row.provider),
      enabled: row.enabled !== false,
      api_keys: Array.isArray(row.api_keys) && row.api_keys.length ? row.api_keys : [''],
      service: String(row.service || 'dr'),
    }))
  return [...known, ...extras]
})

const hasConfiguredKeys = computed(() => providerPools.value.some(pool => (
  pool.api_keys.some((key: string) => String(key || '').trim())
)))

function updateProvider(provider: string, patch: Partial<SmsProviderPool>) {
  const pools = providerPools.value.map(pool => (
    pool.provider === provider ? { ...pool, ...patch, label: undefined } : { ...pool, label: undefined }
  )).map(({ label: _label, ...pool }) => pool)
  const primaryPool = pools.find(pool => pool.provider === 'smsbower')
    || pools.find(pool => pool.enabled && pool.api_keys.some(Boolean))
    || pools[0]
  const keys = (primaryPool?.api_keys || [])
    .map((key: string) => String(key || '').trim())
    .filter(Boolean)
  const enabledPlatforms = pools.filter(pool => (
    pool.enabled && pool.api_keys.some((key: string) => String(key || '').trim())
  )).length
  const attemptsPerProvider = Number(props.modelValue.phone_attempts_per_provider ?? 15)
  emit('update:modelValue', {
    ...props.modelValue,
    sms_provider_pools: pools,
    sms_provider: primaryPool?.provider || 'smsbower',
    sms_api_keys: keys.length ? keys : [''],
    phone_max_attempts: attemptsPerProvider * Math.max(1, enabledPlatforms),
  })
}

function updateAttempts(value: number | undefined) {
  const attemptsPerProvider = Number(value ?? 15)
  const enabledPlatforms = providerPools.value.filter(pool => (
    pool.enabled && pool.api_keys.some((key: string) => String(key || '').trim())
  )).length
  emit('update:modelValue', {
    ...props.modelValue,
    phone_attempts_per_provider: attemptsPerProvider,
    phone_max_attempts: attemptsPerProvider * Math.max(1, enabledPlatforms),
  })
}

function statusesFor(provider: string) {
  return (props.statuses || []).filter(status => (
    String(status.provider || 'smsbower') === provider
  ))
}
</script>

<template>
  <div class="settings-section">
    <div class="section-heading">
      <h2 class="section-title">SMS 接码</h2>
      <el-button
        :icon="Coin"
        :loading="queryingBalances"
        :disabled="!hasConfiguredKeys"
        @click="emit('queryBalances')"
      >查询余额</el-button>
    </div>
    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="SMS 最低价格">
          <el-input
            :model-value="modelValue.sms_min_price || '0.01'"
            @update:model-value="update('sms_min_price', $event)"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="SMS 最高价格">
          <el-input-number
            :model-value="Number(modelValue.max_price || 0.15)"
            :min="0.001"
            :max="0.18"
            :step="0.005"
            :precision="3"
            controls-position="right"
            @update:model-value="update('max_price', String($event ?? 0.15))"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-row :gutter="10">
      <el-col :span="12">
        <el-form-item label="SMS 超时（秒）">
          <el-input-number
            :model-value="Number(modelValue.sms_timeout || 30)"
            :min="1"
            :max="3600"
            controls-position="right"
            @update:model-value="update('sms_timeout', String($event ?? 30))"
          />
        </el-form-item>
      </el-col>
      <el-col :span="12">
        <el-form-item label="每平台最大尝试">
          <el-input-number
            :model-value="Number(modelValue.phone_attempts_per_provider ?? 15)"
            :min="1"
            :max="15"
            controls-position="right"
            @update:model-value="updateAttempts"
          />
        </el-form-item>
      </el-col>
    </el-row>

    <el-form-item label="手机阶段超时（秒）">
      <el-input-number
        :model-value="Number(modelValue.phone_session_cycle_seconds ?? 1800)"
        :min="30"
        :max="1800"
        controls-position="right"
        @update:model-value="update('phone_session_cycle_seconds', Number($event ?? 1800))"
      />
    </el-form-item>

    <el-form-item label="允许 free 账号接码">
      <el-switch
        :model-value="modelValue.allow_free_plan_sms_binding === true"
        @update:model-value="update('allow_free_plan_sms_binding', Boolean($event))"
      />
    </el-form-item>

    <el-form-item label="质量优先与自适应等待">
      <el-switch
        :model-value="modelValue.sms_quality_optimization !== false"
        @update:model-value="update('sms_quality_optimization', Boolean($event))"
      />
    </el-form-item>

    <div class="provider-pools">
      <section v-for="pool in providerPools" :key="pool.provider" class="provider-pool">
        <header class="provider-header">
          <div class="provider-name">
            <strong>{{ pool.label }}</strong>
            <el-tag size="small" effect="plain">{{ pool.service }}</el-tag>
          </div>
          <div class="provider-actions">
            <el-switch
              :model-value="pool.enabled"
              :aria-label="`${pool.label} 启用状态`"
              @update:model-value="updateProvider(pool.provider, { enabled: Boolean($event) })"
            />
            <el-popover placement="bottom-end" :width="240" trigger="click">
              <template #reference>
                <el-tooltip content="平台高级设置" placement="top">
                  <el-button text circle :aria-label="`${pool.label} 高级设置`">
                    <el-icon><Setting /></el-icon>
                  </el-button>
                </el-tooltip>
              </template>
              <el-form-item label="服务代码" class="advanced-item">
                <el-input
                  :model-value="pool.service"
                  @update:model-value="updateProvider(pool.provider, { service: String($event || '') })"
                />
              </el-form-item>
            </el-popover>
          </div>
        </header>
        <SmsApiKeyEditor
          :model-value="pool.api_keys"
          :statuses="statusesFor(pool.provider)"
          :title="`${pool.label} API Key`"
          @update:model-value="updateProvider(pool.provider, { api_keys: $event })"
        />
      </section>
    </div>
  </div>
</template>

<style scoped>
.section-heading { display: flex; align-items: center; justify-content: space-between; min-height: 32px; margin-bottom: 9px; }
.section-title { margin: 0; font-size: 14px; line-height: 20px; font-weight: 680; letter-spacing: 0; }
.settings-section :deep(.el-input-number) { width: 100%; }
.provider-pools { border-top: 1px solid var(--el-border-color-lighter); }
.provider-pool { padding: 9px 0 2px; border-bottom: 1px solid var(--el-border-color-lighter); }
.provider-header { display: flex; align-items: center; justify-content: space-between; min-height: 32px; margin-bottom: 2px; }
.provider-name, .provider-actions { display: flex; align-items: center; gap: 8px; }
.provider-name strong { font-size: 12px; line-height: 18px; font-weight: 650; }
.provider-actions :deep(.el-button) { width: 32px; height: 32px; padding: 0; }
.advanced-item { margin-bottom: 0; }
</style>
