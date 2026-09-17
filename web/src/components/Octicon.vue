<script setup lang="ts">
import { computed } from 'vue'
import { IconList } from '../lib/theme'

const props = defineProps<{ name: string; title?: string }>()
const d = computed(() => IconList[props.name] || IconList.post)
</script>

<template>
  <svg class="octicon" width="16" height="16" :aria-label="title || name">
    <path fill-rule="evenodd" :d="d" />
  </svg>
</template>
