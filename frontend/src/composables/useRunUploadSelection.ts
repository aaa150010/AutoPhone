import { computed, ref } from 'vue'

export interface RunUploadTargets {
  pixel: boolean
  nv: boolean
}

export function useRunUploadSelection(nvConfigured: () => boolean) {
  const visible = ref(false)
  const pixel = ref(false)
  const nv = ref(false)
  const nvDisabled = computed(() => !nvConfigured())

  function open() {
    pixel.value = false
    nv.value = false
    visible.value = true
  }

  function targets(): RunUploadTargets {
    return {
      pixel: pixel.value,
      nv: nv.value && !nvDisabled.value,
    }
  }

  return { visible, pixel, nv, nvDisabled, open, targets }
}
