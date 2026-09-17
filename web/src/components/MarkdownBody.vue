<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { renderMarkdown } from '../lib/markdown'
import { IconList } from '../lib/theme'

const props = defineProps<{ source: string; showToc?: boolean }>()

const root = ref<HTMLElement | null>(null)
const html = computed(() => renderMarkdown(props.source))
const toc = ref<Array<{ id: string; text: string; level: number }>>([])
const lightboxSrc = ref<string | null>(null)

let mermaidReady = false

function slugify(text: string) {
  return (
    text
      .trim()
      .toLowerCase()
      .replace(/\s+/g, '-')
      .replace(/[^\w\u4e00-\u9fff-]/g, '')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '') || 'section'
  )
}

function enhance() {
  const el = root.value
  if (!el) return

  const headings = el.querySelectorAll('h1, h2, h3')
  const seen = new Map<string, number>()
  const items: Array<{ id: string; text: string; level: number }> = []
  headings.forEach((h) => {
    const text = h.textContent || ''
    let id = h.id || slugify(text)
    const n = (seen.get(id) || 0) + 1
    seen.set(id, n)
    if (n > 1) id = `${id}-${n}`
    h.id = id
    items.push({
      id,
      text,
      level: Number(h.tagName.slice(1)),
    })
  })
  toc.value = props.showToc === false ? [] : items.filter((i) => i.level >= 2)

  el.querySelectorAll('pre.hljs').forEach((pre) => {
    if (pre.parentElement?.classList.contains('code-wrap')) return
    const wrap = document.createElement('div')
    wrap.className = 'code-wrap'
    pre.parentNode?.insertBefore(wrap, pre)
    wrap.appendChild(pre)

    const btn = document.createElement('button')
    btn.type = 'button'
    btn.className = 'code-copy btn btn-sm'
    btn.title = 'Copy'
    btn.innerHTML = `<svg class="octicon" width="16" height="16"><path fill-rule="evenodd" d="${IconList.copy}"></path></svg>`
    btn.addEventListener('click', async () => {
      const code = pre.textContent || ''
      try {
        await navigator.clipboard.writeText(code)
        btn.innerHTML = `<svg class="octicon" width="16" height="16"><path fill-rule="evenodd" d="${IconList.check}"></path></svg>`
        setTimeout(() => {
          btn.innerHTML = `<svg class="octicon" width="16" height="16"><path fill-rule="evenodd" d="${IconList.copy}"></path></svg>`
        }, 1500)
      } catch {
        /* ignore */
      }
    })
    wrap.appendChild(btn)
  })

  el.querySelectorAll('img').forEach((img) => {
    if (img.dataset.lb === '1') return
    img.dataset.lb = '1'
    img.style.cursor = 'zoom-in'
    img.addEventListener('click', () => {
      lightboxSrc.value = img.currentSrc || img.src
    })
  })

  void runMermaid(el)
}

async function runMermaid(el: HTMLElement) {
  const nodes = el.querySelectorAll('.mermaid')
  if (!nodes.length) return
  const mermaid = (await import('mermaid')).default
  if (!mermaidReady) {
    mermaid.initialize({
      startOnLoad: false,
      theme:
        document.documentElement.getAttribute('data-color-mode') === 'dark'
          ? 'dark'
          : 'neutral',
      securityLevel: 'loose',
    })
    mermaidReady = true
  }
  try {
    await mermaid.run({ nodes: Array.from(nodes) as HTMLElement[] })
  } catch (e) {
    console.warn('mermaid render failed', e)
  }
}

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') lightboxSrc.value = null
}

onMounted(() => {
  document.addEventListener('keydown', onKey)
  nextTick(enhance)
})

onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKey)
})

watch(html, () => nextTick(enhance))
</script>

<template>
  <div class="md-layout">
    <nav v-if="toc.length > 1" class="post-toc" aria-label="Table of contents">
      <div class="toc-title">Contents</div>
      <a
        v-for="item in toc"
        :key="item.id"
        class="toc-link"
        :class="`lv${item.level}`"
        :href="`#${item.id}`"
        >{{ item.text }}</a
      >
    </nav>
    <div ref="root" class="markdown-body" v-html="html" />
  </div>

  <Teleport to="body">
    <div
      v-if="lightboxSrc"
      class="lightbox"
      role="dialog"
      @click="lightboxSrc = null"
    >
      <img :src="lightboxSrc" alt="" @click.stop />
    </div>
  </Teleport>
</template>

<style scoped>
.md-layout {
  position: relative;
}
.post-toc {
  position: fixed;
  top: 96px;
  right: max(12px, calc((100vw - 900px) / 2 - 180px));
  width: 160px;
  max-height: 70vh;
  overflow: auto;
  font-size: 12px;
  line-height: 1.4;
  padding: 8px;
  border-left: 2px solid var(--color-border-default);
  color: var(--color-fg-muted);
}
.toc-title {
  font-weight: 600;
  margin-bottom: 6px;
  color: var(--color-fg-default);
}
.toc-link {
  display: block;
  color: inherit;
  text-decoration: none;
  margin: 4px 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.toc-link:hover {
  color: var(--color-accent-fg);
}
.toc-link.lv3 {
  padding-left: 10px;
}
@media (max-width: 1200px) {
  .post-toc {
    display: none;
  }
}
.lightbox {
  position: fixed;
  inset: 0;
  z-index: 1000;
  background: rgba(0, 0, 0, 0.82);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  cursor: zoom-out;
}
.lightbox img {
  max-width: 96vw;
  max-height: 92vh;
  object-fit: contain;
  border-radius: 4px;
}
</style>

<style>
.code-wrap {
  position: relative;
}
.code-wrap .code-copy {
  position: absolute;
  top: 8px;
  right: 8px;
  opacity: 0.55;
  padding: 4px 6px;
}
.code-wrap:hover .code-copy {
  opacity: 1;
}
.markdown-body img {
  max-width: 100%;
}
</style>
