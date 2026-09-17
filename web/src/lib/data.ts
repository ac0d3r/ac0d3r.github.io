import type { Post, PostsIndex, SiteConfig } from '../types'

const REPO = 'ac0d3r/ac0d3r.github.io'
const BRANCH = 'main'

/** Local /data in dev; raw.githubusercontent.com in production. */
export function dataBaseUrl(): string {
  if (import.meta.env.DEV) return '/data'
  if (import.meta.env.VITE_DATA_BASE) return import.meta.env.VITE_DATA_BASE
  return `https://raw.githubusercontent.com/${REPO}/${BRANCH}/data`
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-cache' })
  if (!res.ok) throw new Error(`Failed to load ${url}: ${res.status}`)
  return res.json() as Promise<T>
}

export function fetchSite(): Promise<SiteConfig> {
  return fetchJson(`${dataBaseUrl()}/site.json`)
}

export function fetchPostsIndex(): Promise<PostsIndex> {
  return fetchJson(`${dataBaseUrl()}/posts.json`)
}

export function fetchPost(slug: string): Promise<Post> {
  return fetchJson(`${dataBaseUrl()}/posts/${encodeURIComponent(slug)}.json`)
}

export async function fetchIssueComments(repo: string, issueNumber: number) {
  const res = await fetch(
    `https://api.github.com/repos/${repo}/issues/${issueNumber}/comments`,
    {
      headers: { Accept: 'application/vnd.github+json' },
    },
  )
  if (!res.ok) throw new Error(`Failed to load comments: ${res.status}`)
  return res.json() as Promise<
    Array<{
      id: number
      body: string
      created_at: string
      author_association: string
      user: { login: string }
    }>
  >
}
