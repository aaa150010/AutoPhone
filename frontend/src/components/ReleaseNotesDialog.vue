<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { CircleCheck, InfoFilled } from '@element-plus/icons-vue'
import { currentRelease } from '../releaseNotes'
import { acknowledgeReleaseNotes, shouldShowReleaseNotes } from '../utils/releaseNotes'

const visible = ref(false)

function acknowledge() {
  acknowledgeReleaseNotes(window.localStorage, currentRelease.version)
  visible.value = false
}

onMounted(() => {
  visible.value = shouldShowReleaseNotes(window.localStorage, currentRelease.version)
})
</script>

<template>
  <el-dialog
    :model-value="visible"
    class="release-notes-dialog"
    width="640px"
    :show-close="false"
    :close-on-click-modal="false"
    :close-on-press-escape="false"
    align-center
  >
    <template #header>
      <div class="release-header">
        <el-icon><InfoFilled /></el-icon>
        <div>
          <strong>{{ currentRelease.title }}</strong>
          <span>版本 {{ currentRelease.version }} · {{ currentRelease.releasedAt }}</span>
        </div>
      </div>
    </template>

    <div class="release-sections">
      <section v-for="section in currentRelease.sections" :key="section.title">
        <h3>{{ section.title }}</h3>
        <p>{{ section.usage }}</p>
      </section>
    </div>

    <template #footer>
      <el-button type="primary" @click="acknowledge"><el-icon><CircleCheck /></el-icon>我知道了</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.release-header { display: flex; align-items: center; gap: 11px; }
.release-header > .el-icon { flex: 0 0 auto; color: var(--el-color-primary); font-size: 28px; }
.release-header div { display: flex; flex-direction: column; gap: 3px; }
.release-header strong { color: #172033; font-size: 17px; }
.release-header span { color: #8490a3; font-size: 12px; }
.release-sections { display: grid; gap: 0; border: 1px solid var(--workspace-border); }
.release-sections section { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 14px; padding: 13px 15px; }
.release-sections section + section { border-top: 1px solid var(--workspace-border); }
.release-sections h3 { margin: 0; color: #253047; font-size: 13px; line-height: 1.6; }
.release-sections p { margin: 0; color: #596579; font-size: 13px; line-height: 1.65; }
</style>
