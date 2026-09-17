<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, RouterLink } from 'vue-router'
import Octicon from '../components/Octicon.vue'
import MarkdownBody from '../components/MarkdownBody.vue'
import { fetchIssueComments, fetchPost } from '../lib/data'
import { renderMarkdown } from '../lib/markdown'
import { useBlog } from '../composables/useBlog'
import {
  applyTheme,
  getStoredTheme,
  nextTheme,
  themeIcon,
  type ThemeMode,
} from '../lib/theme'
import type { Post } from '../types'

const props = defineProps<{ slug: string }>()
const route = useRoute()
const { site, ensureLoaded } = useBlog()
const post = ref<Post | null>(null)
const entries = ref<Array<{ created_at: string; html: string }>>([])
const error = ref<string | null>(null)
const loading = ref(true)
const theme = ref<ThemeMode>(getStoredTheme())

const pageSlug = computed(() => props.slug || String(route.params.slug || ''))

function formatTime(iso: string) {
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

async function load() {
  loading.value = true
  error.value = null
  try {
    await ensureLoaded()
    const loaded = await fetchPost(pageSlug.value)
    post.value = loaded
    document.title = loaded.title
    const repo = site.value?.repo || 'ac0d3r/ac0d3r.github.io'
    const comments = await fetchIssueComments(repo, loaded.number)
    const owner = repo.split('/')[0]
    entries.value = comments
      .filter(
        (c) =>
          c.author_association === 'OWNER' || c.user?.login === owner,
      )
      .sort(
        (a, b) =>
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      )
      .map((c) => ({
        created_at: c.created_at,
        html: renderMarkdown(c.body || ''),
      }))
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
watch(pageSlug, load)

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
      <section v-if="post.body" class="talks-intro">
        <MarkdownBody :source="post.body" />
      </section>
      <section class="talks-timeline">
        <p v-if="entries.length === 0" class="talks-empty">No entries yet.</p>
        <article v-for="(entry, i) in entries" :key="i" class="talk-entry">
          <div class="talk-entry-dot" />
          <div class="talk-entry-main">
            <time class="talk-entry-time">{{ formatTime(entry.created_at) }}</time>
            <div class="talk-entry-body markdown-body" v-html="entry.html" />
          </div>
        </article>
      </section>
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
.talks-intro {
  margin-bottom: 32px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--color-border-default);
}
.talks-timeline {
  position: relative;
  padding-left: 32px;
}
.talks-timeline:before {
  content: '';
  position: absolute;
  left: 10px;
  top: 4px;
  bottom: 4px;
  width: 2px;
  background: linear-gradient(
    to bottom,
    var(--color-accent-fg),
    var(--color-border-default)
  );
}
.talk-entry {
  position: relative;
  margin-bottom: 28px;
}
.talk-entry-dot {
  position: absolute;
  left: -32px;
  top: 5px;
  width: 12px;
  height: 12px;
  border-radius: 999px;
  background: var(--color-accent-fg);
  box-shadow: 0 0 0 4px var(--color-canvas-default);
}
.talk-entry-time {
  display: block;
  margin-bottom: 10px;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.04em;
  color: var(--color-fg-muted);
}
.talk-entry-body {
  padding: 14px 16px;
  border: 1px solid var(--color-border-default);
  border-radius: 14px;
  background: var(--color-canvas-subtle);
  font-size: 13px;
  line-height: 1.3;
}
.talks-empty,
.muted {
  color: var(--color-fg-muted);
}
@media (max-width: 600px) {
  .postTitle {
    font-size: 20px;
  }
  .talks-timeline {
    padding-left: 24px;
  }
  .talk-entry-dot {
    left: -24px;
  }
}
</style>
