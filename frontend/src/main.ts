import { createApp } from 'vue'
import './styles/base.css'
import App from './App.vue'
// Element Plus resolves on demand via unplugin-vue-components/AutoImport in
// vite.config.ts; no full-library import here keeps the bundle to used parts.
createApp(App).mount('#app')
