import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import './styles/main.css'
import { applyTheme, getStoredTheme } from './lib/theme'

applyTheme(getStoredTheme())

createApp(App).use(router).mount('#app')
