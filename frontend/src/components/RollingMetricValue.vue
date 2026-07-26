<script setup lang="ts">
import { computed, ref, watch } from 'vue'

const props = defineProps<{ value: number }>()
const direction = ref<'up' | 'down'>('up')
const formattedValue = computed(() => String(props.value))

watch(
  () => props.value,
  (next, previous) => {
    direction.value = next >= previous ? 'up' : 'down'
  },
)
</script>

<template>
  <span class="rolling-value" :aria-label="formattedValue">
    <Transition :name="`metric-roll-${direction}`">
      <span :key="formattedValue" class="rolling-value__item" aria-hidden="true">
        {{ formattedValue }}
      </span>
    </Transition>
  </span>
</template>

<style scoped>
.rolling-value {
  display: inline-grid;
  min-width: 1ch;
  overflow: hidden;
  line-height: inherit;
  vertical-align: bottom;
}
.rolling-value__item {
  grid-area: 1 / 1;
  line-height: inherit;
  will-change: transform, opacity;
}
.metric-roll-up-enter-active,
.metric-roll-up-leave-active,
.metric-roll-down-enter-active,
.metric-roll-down-leave-active {
  transition: transform 360ms cubic-bezier(0.22, 1, 0.36, 1), opacity 240ms ease;
}
.metric-roll-up-enter-from { opacity: 0; transform: translateY(100%); }
.metric-roll-up-leave-to { opacity: 0; transform: translateY(-100%); }
.metric-roll-down-enter-from { opacity: 0; transform: translateY(-100%); }
.metric-roll-down-leave-to { opacity: 0; transform: translateY(100%); }
@media (prefers-reduced-motion: reduce) {
  .metric-roll-up-enter-active,
  .metric-roll-up-leave-active,
  .metric-roll-down-enter-active,
  .metric-roll-down-leave-active { transition: none; }
}
</style>
