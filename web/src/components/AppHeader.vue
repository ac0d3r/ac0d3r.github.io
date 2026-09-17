<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import Octicon from './Octicon.vue'
import { useBlog } from '../composables/useBlog'
import {
  applyTheme,
  getStoredTheme,
  nextTheme,
  themeIcon,
  type ThemeMode,
} from '../lib/theme'

const { site, pages, ensureLoaded } = useBlog()
const theme = ref<ThemeMode>(getStoredTheme())

onMounted(async () => {
  applyTheme(theme.value)
  await ensureLoaded()
})

function toggleTheme() {
  theme.value = nextTheme(theme.value)
  applyTheme(theme.value)
}

function pageIcon(slug: string, title: string) {
  if (slug === 'about') return 'about'
  if (slug === 'talks') return 'talks'
  if (slug === 'daily-reversing') return 'daily-reversing'
  return title
}
</script>

<template>
  <header id="header" v-if="site">
    <div class="title-left">
      <RouterLink to="/">
        <img :src="site.avatarUrl" class="blog-avatar" alt="avatar" />
        <span class="blogTitle">{{ site.title }}</span>
      </RouterLink>
    </div>
    <div class="title-right">
      <RouterLink to="/tag" class="btn btn-invisible circle" title="Search">
        <Octicon name="search" />
      </RouterLink>
      <a
        v-for="(url, key) in site.exlink"
        :key="key"
        :href="url"
        class="btn btn-invisible circle"
        :title="String(key)"
        target="_blank"
        rel="noopener"
      >
        <Octicon :name="String(key)" />
      </a>
      <RouterLink
        v-for="page in pages"
        :key="page.slug"
        :to="`/${page.slug}`"
        class="btn btn-invisible circle"
        :title="page.title"
      >
        <Octicon :name="pageIcon(page.slug, page.title)" />
      </RouterLink>
      <a
        href="/rss.xml"
        id="buttonRSS"
        class="btn btn-invisible circle"
        title="RSS"
        target="_blank"
        rel="noopener"
      >
        <Octicon name="rss" />
      </a>
      <button
        v-if="site.themeMode === 'manual'"
        type="button"
        class="btn btn-invisible circle"
        title="switch theme"
        @click="toggleTheme"
      >
        <svg class="octicon" width="16" height="16">
          <path fill-rule="evenodd" :d="themeIcon(theme)" />
        </svg>
      </button>
    </div>
  </header>
</template>

<style scoped>
.title-left a {
  color: inherit;
  text-decoration: none;
  display: flex;
  align-items: center;
}
.blog-avatar {
  transition: 0.8s;
  width: 64px;
  height: 64px;
  object-fit: cover;
  background: transparent;
  border-radius: 0;
  box-shadow: none;
}
.blogTitle {
  vertical-align: bottom;
  font-size: 32px;
  font-weight: bold;
  font-family: Monaco, monospace;
  margin-left: 8px;
}
.title-right {
  display: flex;
  margin: auto 0 0 auto;
  align-items: center;
}
.title-right .circle {
  padding: 14px 16px;
}
@media (max-width: 600px) {
  .blog-avatar {
    width: 40px;
    height: 40px;
  }
  .blogTitle {
    display: none;
  }
  #buttonRSS {
    display: none;
  }
}
</style>
