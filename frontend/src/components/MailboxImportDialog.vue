<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Upload } from '@element-plus/icons-vue'
import { importMailboxes } from '../api/client'

type ImportResult = Awaited<ReturnType<typeof importMailboxes>>

const emit = defineEmits<{
  imported: [ImportResult]
  busyChange: [boolean]
}>()

const visible = ref(false)
const content = ref('')
const loading = ref(false)

function open() {
  visible.value = true
}

async function submit() {
  if (loading.value) return
  if (!content.value.trim()) {
    ElMessage.warning('请先粘贴要导入的邮箱')
    return
  }
  loading.value = true
  emit('busyChange', true)
  try {
    const result = await importMailboxes(content.value)
    content.value = ''
    visible.value = false
    emit('imported', result)
    ElMessage.success(`已追加 ${result.imported || 0} 条，跳过 ${result.skipped || 0} 条`)
  } catch (error: any) {
    ElMessage.error(error?.message || '导入失败')
  } finally {
    loading.value = false
    emit('busyChange', false)
  }
}

defineExpose({ open })
</script>

<template>
  <el-dialog
    v-model="visible"
    title="批量追加邮箱"
    width="720px"
    destroy-on-close
    :close-on-click-modal="!loading"
    :close-on-press-escape="!loading"
    :show-close="!loading"
  >
    <el-input
      v-model="content"
      type="textarea"
      :rows="12"
      resize="none"
      placeholder="URL 邮箱：邮箱---https://接码地址&#10;密码+URL：邮箱----登录密码----https://接码地址&#10;URL+密码：邮箱----https://接码地址----密码：登录密码&#10;TOTP：GPT账号---登录密码---Base32 2FA密钥&#10;TOTP：GPT账号|登录密码|Base32 2FA密钥&#10;OAuth：邮箱----密码----client_id----refresh_token&#10;&#10;URL 邮箱支持 --- / ---- / | / ｜"
    />
    <template #footer>
      <el-button :disabled="loading" @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="loading" @click="submit">
        <el-icon><Upload /></el-icon>追加导入
      </el-button>
    </template>
  </el-dialog>
</template>
