import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import * as Icons from '@element-plus/icons-vue'
import 'element-plus/dist/index.css'
import './styles/base.css'
import App from './App.vue'
const app=createApp(App); for(const [name,component] of Object.entries(Icons)) app.component(name, component); app.use(ElementPlus).mount('#app')
