<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, RouterLink } from 'vue-router'
import AppHeader from '../components/AppHeader.vue'
import PostListItem from '../components/PostListItem.vue'
import type { PostMeta } from '../types'
import { useBlog } from '../composables/useBlog'

const route = useRoute()
const { site, posts, ensureLoaded } = useBlog()
const ready = ref(false)

const activeLabel = computed(() =>
  route.params.label ? decodeURIComponent(String(route.params.label)) : '',
)

const allLabels = computed(() => {
  const map = new Map<string, { count: number; color: string }>()
  for (const post of posts.value) {
    for (const label of post.labels) {
      const prev = map.get(label)
      map.set(label, {
        count: (prev?.count || 0) + 1,
        color:
          post.labelColors[label] ||
          site.value?.labelColors[label] ||
          '#6e7781',
      })
    }
  }
  return [...map.entries()]
    .map(([name, meta]) => ({ name, ...meta }))
    .sort((a, b) => a.name.localeCompare(b.name))
})

const filtered = computed(() => {
  if (!activeLabel.value) return [] as PostMeta[]
  return posts.value.filter((p: PostMeta) => p.labels.includes(activeLabel.value))
})

onMounted(async () => {
  await ensureLoaded()
  ready.value = true
  document.title = activeLabel.value
    ? `Tag: ${activeLabel.value}`
    : 'Tags'
})
</script>

<template>
  <AppHeader />
  <div id="content">
    <p v-if="!ready" class="muted">Loading...</p>
    <template v-else-if="!activeLabel">
      <div class="tag-cloud">
        <RouterLink
          v-for="label in allLabels"
          :key="label.name"
          class="Label tag-item"
          :to="`/tag/${encodeURIComponent(label.name)}`"
          :style="{ backgroundColor: label.color }"
        >
          {{ label.name }}
          <span class="Counter">{{ label.count }}</span>
        </RouterLink>
      </div>
    </template>
    <template v-else>
      <h2 class="tag-heading">
        <span class="Label" :style="{ backgroundColor: site?.labelColors[activeLabel] }">{{
          activeLabel
        }}</span>
      </h2>
      <nav class="SideNav border">
        <PostListItem v-for="post in filtered" :key="post.number" :post="post" />
      </nav>
    </template>
  </div>
</template>

<style scoped>
.tag-cloud {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.tag-item {
  color: #fff !important;
  text-decoration: none;
  padding: 4px 8px;
}
.tag-heading {
  margin-bottom: 16px;
}
.muted {
  color: var(--color-fg-muted);
}
</style>
