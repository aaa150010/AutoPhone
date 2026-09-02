import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:18777',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Element Plus is intentionally installed as one desktop UI vendor chunk.
    // Keep the warning threshold above that stable chunk while preserving
    // warnings for unexpected application or dependency growth.
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      onwarn(warning, warn) {
        const dependencyId = String(warning.id || '').replaceAll('\\', '/')
        if (warning.code === 'INVALID_ANNOTATION' && dependencyId.includes('/node_modules/@vueuse/core/')) return
        warn(warning)
      },
      output: {
        manualChunks(id) {
          const moduleId = id.replaceAll('\\', '/')
          if (moduleId.includes('/node_modules/@element-plus/icons-vue/')) return 'element-icons'
          if (moduleId.includes('/node_modules/element-plus/')) return 'element-plus'
          if (moduleId.includes('/node_modules/@vueuse/')) return 'vueuse'
          if (moduleId.includes('/node_modules/vue/') || moduleId.includes('/node_modules/@vue/')) return 'vue'
          return undefined
        },
      },
    },
  },
})
