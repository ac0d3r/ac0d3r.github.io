<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { getStoredTheme, utterancesTheme } from '../lib/theme'

const props = defineProps<{
  repo: string
  term: string
}>()

const box = ref<HTMLElement | null>(null)
let opened = false

function mountUtterances() {
  if (!box.value || opened) return
  opened = true
  box.value.innerHTML = ''
  const script = document.createElement('script')
  script.src = 'https://utteranc.es/client.js'
  script.setAttribute('repo', props.repo)
  script.setAttribute('issue-term', 'title')
  script.setAttribute('theme', utterancesTheme(getStoredTheme()))
  script.setAttribute('crossorigin', 'anonymous')
  script.async = true
  box.value.appendChild(script)
}

onMounted(mountUtterances)
watch(
  () => [props.repo, props.term],
  () => {
    opened = false
    mountUtterances()
  },
)

onBeforeUnmount(() => {
  if (box.value) box.value.innerHTML = ''
  opened = false
})
</script>

<template>
  <div class="comments" ref="box" />
</template>
