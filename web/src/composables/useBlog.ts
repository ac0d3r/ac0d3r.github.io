import { computed, ref } from 'vue'
import { fetchPostsIndex, fetchSite } from '../lib/data'
import type { PostsIndex, SiteConfig } from '../types'

const site = ref<SiteConfig | null>(null)
const index = ref<PostsIndex | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)

let bootPromise: Promise<void> | null = null

export function useBlog() {
  async function ensureLoaded() {
    if (site.value && index.value) return
    if (bootPromise) return bootPromise
    bootPromise = (async () => {
      loading.value = true
      error.value = null
      try {
        const [s, i] = await Promise.all([fetchSite(), fetchPostsIndex()])
        site.value = s
        index.value = i
      } catch (e) {
        error.value = e instanceof Error ? e.message : String(e)
        throw e
      } finally {
        loading.value = false
      }
    })()
    return bootPromise
  }

  const posts = computed(() => index.value?.posts ?? [])
  const pages = computed(() => index.value?.pages ?? [])

  return { site, index, posts, pages, loading, error, ensureLoaded }
}
