<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useBlog } from '../composables/useBlog'

const { site, ensureLoaded } = useBlog()

onMounted(() => ensureLoaded())

const runDays = computed(() => {
  if (!site.value?.startSite) return ''
  const start = new Date(site.value.startSite)
  const diff = Date.now() - start.getTime()
  const days = Math.floor(diff / (1000 * 60 * 60 * 24))
  const run = site.value.i18n === 'CN' ? '网站运行' : 'run '
  const unit = site.value.i18n === 'CN' ? '天' : ' days'
  return `${run}${days}${unit} • `
})

const year = new Date().getFullYear()
</script>

<template>
  <footer id="footer" v-if="site">
    <div>
      Copyright © {{ year }}
      <a :href="site.homeUrl || '/'">{{ site.title }}</a>
    </div>
    <div>
      <span>{{ runDays }}</span>
      <span v-if="site.filingNum">
        <a href="https://beian.miit.gov.cn/" target="_blank" rel="noopener">{{
          site.filingNum
        }}</a>
        •
      </span>
    </div>
  </footer>
</template>
