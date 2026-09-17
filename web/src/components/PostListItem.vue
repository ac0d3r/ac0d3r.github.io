<script setup lang="ts">
import { RouterLink } from 'vue-router'
import type { PostMeta } from '../types'

defineProps<{ post: PostMeta }>()
</script>

<template>
  <RouterLink class="SideNav-item d-flex flex-items-center" :to="`/post/${post.slug}`">
    <div class="d-flex flex-auto">
      <span class="listTitle">{{ post.title }}</span>
      <div class="listLabels">
        <span
          v-for="label in post.labels"
          :key="label"
          class="Label"
          :style="{ backgroundColor: post.labelColors[label] || '#6e7781' }"
          >{{ label }}</span
        >
        <span
          class="Label LabelTime"
          :style="{ backgroundColor: post.dateLabelColor }"
          >{{ post.createdDate }}</span
        >
      </div>
    </div>
  </RouterLink>
</template>
