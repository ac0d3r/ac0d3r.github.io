<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, RouterLink } from 'vue-router'
import Octicon from '../components/Octicon.vue'
import MarkdownBody from '../components/MarkdownBody.vue'
import Utterances from '../components/Utterances.vue'
import { fetchPost } from '../lib/data'
import { useBlog } from '../composables/useBlog'
import {
  applyTheme,
  getStoredTheme,
  nextTheme,
  themeIcon,
  type ThemeMode,
} from '../lib/theme'
import type { Post } from '../types'

const route = useRoute()
const { site, ensureLoaded } = useBlog()
const post = ref<Post | null>(null)
const error = ref<string | null>(null)
const loading = ref(true)
const theme = ref<ThemeMode>(getStoredTheme())
const showComments = ref(false)

const slug = computed(() => String(route.params.slug || ''))

async function load() {
  loading.value = true
  error.value = null
  showComments.value = false
  try {
    await ensureLoaded()
    const loaded = await fetchPost(slug.value)
    post.value = loaded
    document.title = loaded.title
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  applyTheme(theme.value)
  load()
})
watch(slug, load)

function toggleTheme() {
  theme.value = nextTheme(theme.value)
  applyTheme(theme.value)
}
</script>

<template>
  <header id="header">
    <h1 class="postTitle">{{ post?.title || '…' }}</h1>
    <div class="title-right">
      <RouterLink to="/" class="btn btn-invisible circle" title="home">
        <Octicon name="home" />
      </RouterLink>
      <button
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
  <div id="content">
    <p v-if="loading" class="muted">Loading...</p>
    <p v-else-if="error" class="muted">{{ error }}</p>
    <template v-else-if="post">
      <MarkdownBody :source="post.body" />
      <template v-if="post.needComment && site">
        <button
          v-if="!showComments"
          class="btn btn-block"
          type="button"
          @click="showComments = true"
        >
          comments
        </button>
        <Utterances v-if="showComments" :repo="site.repo" :term="post.title" />
      </template>
    </template>
  </div>
</template>

<style scoped>
.postTitle {
  margin: auto 0;
  font-size: 32px;
  font-weight: bold;
}
.title-right {
  display: flex;
  margin: auto 0 0 auto;
}
.title-right .circle {
  padding: 14px 16px;
  margin-right: 8px;
}
.muted {
  color: var(--color-fg-muted);
}
@media (max-width: 600px) {
  .postTitle {
    font-size: 20px;
  }
}
</style>
