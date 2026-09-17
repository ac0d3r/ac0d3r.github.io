<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AppHeader from '../components/AppHeader.vue'
import PostListItem from '../components/PostListItem.vue'
import { useBlog } from '../composables/useBlog'

const route = useRoute()
const router = useRouter()
const { site, posts, loading, error, ensureLoaded } = useBlog()
const ready = ref(false)

const pageSize = computed(() => site.value?.onePageListNum || 15)
const totalPages = computed(() =>
  Math.max(1, Math.ceil(posts.value.length / pageSize.value)),
)
const currentPage = computed(() => {
  const raw = Number(route.query.page || 1)
  if (!Number.isFinite(raw) || raw < 1) return 1
  return Math.min(raw, totalPages.value)
})
const pagePosts = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return posts.value.slice(start, start + pageSize.value)
})

const prevLabel = computed(() =>
  site.value?.i18n === 'CN' ? '上一页' : 'Previous',
)
const nextLabel = computed(() =>
  site.value?.i18n === 'CN' ? '下一页' : 'Next',
)

function goPage(page: number) {
  if (page < 1 || page > totalPages.value) return
  router.push(page <= 1 ? { path: '/' } : { path: '/', query: { page } })
}

onMounted(async () => {
  try {
    await ensureLoaded()
  } finally {
    ready.value = true
  }
  document.title = site.value?.title || 'Blog'
})

watch(
  () => site.value?.title,
  (t) => {
    if (t) document.title = t
  },
)
</script>

<template>
  <AppHeader />
  <div id="content">
    <p v-if="site?.subTitle" class="sub-title">{{ site.subTitle }}</p>
    <p v-if="!ready || loading" class="muted">Loading...</p>
    <p v-else-if="error" class="muted">{{ error }}</p>
    <template v-else>
      <nav class="SideNav border" style="max-width: 100%">
        <PostListItem
          v-for="post in pagePosts"
          :key="post.number"
          :post="post"
        />
      </nav>
      <div v-if="totalPages > 1" class="pager">
        <button
          type="button"
          class="btn"
          :disabled="currentPage <= 1"
          @click="goPage(currentPage - 1)"
        >
          {{ prevLabel }}
        </button>
        <span class="page-info">{{ currentPage }} / {{ totalPages }}</span>
        <button
          type="button"
          class="btn"
          :disabled="currentPage >= totalPages"
          @click="goPage(currentPage + 1)"
        >
          {{ nextLabel }}
        </button>
      </div>
    </template>
  </div>
</template>

<style scoped>
.sub-title {
  margin: 0 0 16px;
  color: var(--color-fg-muted);
  font-size: 15px;
}
.muted {
  color: var(--color-fg-muted);
}
.SideNav {
  min-width: 0;
}
.pager {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  margin-top: 24px;
}
.page-info {
  color: var(--color-fg-muted);
  font-size: 13px;
}
</style>
