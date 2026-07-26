<script setup lang="ts">
defineProps<{ modelValue: string; secretId: string; label: string; placeholder?: string; disabled?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [string] }>()
</script>
<template>
  <el-form-item :label="label">
    <el-input :model-value="modelValue" type="password" :placeholder="placeholder" :disabled="disabled" autocomplete="new-password" :show-password="true" @update:model-value="emit('update:modelValue', $event)" />
  </el-form-item>
</template>
