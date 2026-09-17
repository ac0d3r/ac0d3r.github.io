import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import PostView from '../views/PostView.vue'
import TagView from '../views/TagView.vue'
import PageView from '../views/PageView.vue'
import TimelineView from '../views/TimelineView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { path: '/', name: 'home', component: HomeView },
    { path: '/tag', name: 'tags', component: TagView },
    { path: '/tag/:label', name: 'tag', component: TagView },
    { path: '/post/:slug', name: 'post', component: PostView },
    {
      path: '/talks',
      name: 'talks',
      component: TimelineView,
      props: { slug: 'talks' },
    },
    {
      path: '/daily-reversing',
      name: 'daily-reversing',
      component: TimelineView,
      props: { slug: 'daily-reversing' },
    },
    { path: '/:slug', name: 'page', component: PageView },
  ],
  scrollBehavior() {
    return { top: 0 }
  },
})

export default router
