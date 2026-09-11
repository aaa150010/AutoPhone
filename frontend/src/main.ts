import { createApp } from 'vue'
import './styles/base.css'
// Component JS resolves on demand via unplugin-vue-components/AutoImport, but
// imperative APIs (ElMessage/ElMessageBox/ElNotification) are imported
// directly in 27+ files, which bypasses the resolvers; the full stylesheet is
// required or those popups render unstyled.
import 'element-plus/dist/index.css'
import App from './App.vue'
createApp(App).mount('#app')
