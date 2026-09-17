#!/usr/bin/env node
/**
 * Sync GitHub Issues → data/*.json (Markdown body, no comments).
 *
 *   GITHUB_TOKEN=xxx node scripts/sync-data.mjs [owner/repo]
 *
 * Token optional for public repos (60 req/h unauthenticated).
 * Prefer a token in CI / frequent local runs.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { pinyin } from 'pinyin-pro'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, '../..')
const DATA_DIR = path.join(ROOT, 'data')
const POSTS_DIR = path.join(DATA_DIR, 'posts')

const YEAR_COLORS = ['#bc4c00', '#0969da', '#1f883d', '#A333D0']

function loadConfig() {
  const cfgPath = path.join(ROOT, 'config.json')
  const defaults = {
    singlePage: [],
    useTimeline: [],
    urlMode: 'pinyin',
    i18n: 'EN',
    UTC: 8,
    yearColorList: YEAR_COLORS,
    needComment: 1,
    onePageListNum: 15,
    themeMode: 'manual',
    dayTheme: 'light',
    nightTheme: 'dark',
    startSite: '',
    filingNum: '',
    bottomText: '',
    exlink: {},
    avatarUrl: '/imgs/avatar.png',
    homeUrl: '',
    title: '',
    subTitle: '',
  }
  const user = JSON.parse(fs.readFileSync(cfgPath, 'utf8'))
  return { ...defaults, ...user }
}

function sanitizeSlug(name) {
  return name.replace(/[<>:/\\|?*"\0-\x1f]/g, '-')
}

function createSlugForIssue(issue, config) {
  const labels = (issue.labels || []).map((l) => (typeof l === 'string' ? l : l.name))
  const singlePage = config.singlePage || []
  if (labels[0] && singlePage.includes(labels[0])) {
    return sanitizeSlug(labels[0])
  }
  if (config.urlMode === 'issue') {
    return String(issue.number)
  }
  if (config.i18n === 'EN') {
    return sanitizeSlug(issue.title.trim().toLowerCase().replace(/ /g, '-'))
  }
  if (config.urlMode === 'pinyin') {
    return sanitizeSlug(pinyin(issue.title, { toneType: 'none', type: 'array' }).join('-'))
  }
  return sanitizeSlug(issue.title.trim().toLowerCase().replace(/ /g, '-'))
}

function parsePostConfig(body) {
  if (!body) return {}
  const lines = body.trim().split(/\r?\n/)
  let tail = (lines[lines.length - 1] || '').trim()
  if (tail.includes('##')) tail = tail.split('##').pop().trim()
  if (!(tail.startsWith('{') && tail.endsWith('}'))) return {}
  try {
    return JSON.parse(tail)
  } catch {
    return {}
  }
}

function stripPostConfig(body) {
  if (!body) return ''
  const lines = body.trimEnd().split(/\r?\n/)
  let tail = (lines[lines.length - 1] || '').trim()
  if (tail.includes('##')) tail = tail.split('##').pop().trim()
  if (tail.startsWith('{') && tail.endsWith('}')) {
    try {
      JSON.parse(tail)
      return lines.slice(0, -1).join('\n').trimEnd()
    } catch {
      /* keep */
    }
  }
  return body
}

function excerptFrom(body, i18n) {
  if (!body) return ''
  const period = i18n === 'CN' ? '。' : '.'
  const part = body.split(period)[0] || ''
  return (part.replace(/"/g, "'") + period).slice(0, 280)
}

function dateLabelColor(createdAt, yearColors) {
  const year = new Date(createdAt * 1000).getFullYear()
  return yearColors[year % yearColors.length]
}

function formatDate(createdAt, utcOffset) {
  const local = new Date(createdAt * 1000)
  const shifted = new Date(local.getTime() + utcOffset * 3600 * 1000)
  const y = shifted.getUTCFullYear()
  const m = String(shifted.getUTCMonth() + 1).padStart(2, '0')
  const day = String(shifted.getUTCDate()).padStart(2, '0')
  return `${y}-${m}-${day}`
}

async function ghFetch(url, token) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'ac0d3r-blog-sync',
  }
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(url, { headers })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status} ${url}: ${text}`)
  }
  return res.json()
}

async function fetchAllIssues(repo, token, creator) {
  const issues = []
  let page = 1
  while (true) {
    const q = new URLSearchParams({
      state: 'all',
      per_page: '100',
      page: String(page),
      creator,
    })
    const batch = await ghFetch(
      `https://api.github.com/repos/${repo}/issues?${q}`,
      token,
    )
    const onlyIssues = batch.filter((i) => !i.pull_request)
    issues.push(...onlyIssues)
    if (batch.length < 100) break
    page += 1
  }
  return issues
}

async function fetchLabels(repo, token) {
  const labels = await ghFetch(
    `https://api.github.com/repos/${repo}/labels?per_page=100`,
    token,
  )
  const dict = {}
  for (const l of labels) dict[l.name] = `#${l.color}`
  return dict
}

function ensureDirs() {
  fs.mkdirSync(POSTS_DIR, { recursive: true })
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n', 'utf8')
}

function buildPostRecord(issue, config, labelColors) {
  const labels = (issue.labels || []).map((l) => (typeof l === 'string' ? l : l.name))
  const postConfig = parsePostConfig(issue.body || '')
  const bodyMd = stripPostConfig(issue.body || '')
  const createdAt =
    typeof postConfig.timestamp === 'number'
      ? postConfig.timestamp
      : Math.floor(new Date(issue.created_at).getTime() / 1000)

  const yearColors = config.yearColorList || YEAR_COLORS
  const slug = createSlugForIssue({ ...issue, labels }, config)
  const isSingle = labels[0] && (config.singlePage || []).includes(labels[0])
  const isTimeline = labels[0] && (config.useTimeline || []).includes(labels[0])

  return {
    number: issue.number,
    title: issue.title,
    slug,
    labels,
    createdAt,
    createdDate: formatDate(createdAt, config.UTC ?? 8),
    dateLabelColor: dateLabelColor(createdAt, yearColors),
    updatedAt: issue.updated_at,
    excerpt: excerptFrom(bodyMd, config.i18n),
    wordCount: bodyMd.length,
    top: 0,
    singlePage: Boolean(isSingle),
    timeline: Boolean(isTimeline),
    needComment: config.needComment !== 0 && !isTimeline,
    ogImage: postConfig.ogImage || config.avatarUrl || '/imgs/avatar.png',
    body: bodyMd,
    labelColors: Object.fromEntries(
      labels.map((name) => [name, labelColors[name] || '#6e7781']),
    ),
  }
}

function writeRss(config, posts) {
  const home = (config.homeUrl || '').replace(/\/$/, '')
  const items = posts
    .filter((p) => !p.singlePage)
    .slice(0, 50)
    .map((p) => {
      const link = `${home}/post/${encodeURIComponent(p.slug)}`
      const date = new Date(p.createdAt * 1000).toUTCString()
      const desc = escapeXml(p.excerpt || '')
      return `    <item>
      <title>${escapeXml(p.title)}</title>
      <link>${link}</link>
      <guid isPermaLink="true">${link}</guid>
      <pubDate>${date}</pubDate>
      <description>${desc}</description>
    </item>`
    })
    .join('\n')

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>${escapeXml(config.title || '')}</title>
    <link>${home}/</link>
    <description>${escapeXml(config.subTitle || '')}</description>
    <language>${config.i18n === 'CN' ? 'zh-cn' : 'en'}</language>
${items}
  </channel>
</rss>
`
  fs.writeFileSync(path.join(DATA_DIR, 'rss.xml'), xml, 'utf8')
  const publicRss = path.join(ROOT, 'web', 'public', 'rss.xml')
  fs.mkdirSync(path.dirname(publicRss), { recursive: true })
  fs.writeFileSync(publicRss, xml, 'utf8')
}

function escapeXml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function writeSiteAndPosts(config, posts, labelColors, repo) {
  ensureDirs()

  const site = {
    title: config.title,
    subTitle: config.subTitle,
    avatarUrl: config.avatarUrl,
    homeUrl: config.homeUrl,
    startSite: config.startSite,
    filingNum: config.filingNum || '',
    bottomText: config.bottomText || '',
    i18n: config.i18n,
    themeMode: config.themeMode,
    dayTheme: config.dayTheme,
    nightTheme: config.nightTheme,
    needComment: config.needComment,
    onePageListNum: config.onePageListNum ?? 15,
    singlePage: config.singlePage || [],
    useTimeline: config.useTimeline || [],
    exlink: config.exlink || {},
    repo,
    labelColors,
    generatedAt: new Date().toISOString(),
  }
  writeJson(path.join(DATA_DIR, 'site.json'), site)

  const list = posts
    .map(({ body, ...meta }) => meta)
    .sort((a, b) => {
      if (b.top !== a.top) return b.top - a.top
      return b.createdAt - a.createdAt
    })

  writeJson(path.join(DATA_DIR, 'posts.json'), {
    posts: list.filter((p) => !p.singlePage),
    pages: list.filter((p) => p.singlePage),
  })

  for (const post of posts) {
    writeJson(path.join(POSTS_DIR, `${post.slug}.json`), post)
  }

  const keep = new Set(posts.map((p) => `${p.slug}.json`))
  for (const name of fs.readdirSync(POSTS_DIR)) {
    if (name.endsWith('.json') && !keep.has(name)) {
      fs.unlinkSync(path.join(POSTS_DIR, name))
    }
  }

  writeRss(config, posts)
  console.log(`Wrote ${posts.length} posts → ${DATA_DIR}`)
}

async function main() {
  const args = process.argv.slice(2)
  const repoArg = args.find((a) => !a.startsWith('--'))
  const repo =
    repoArg ||
    process.env.GITHUB_REPOSITORY ||
    'ac0d3r/ac0d3r.github.io'
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || ''
  if (!token) {
    console.warn('No GITHUB_TOKEN; using unauthenticated API (60 req/h limit)')
  }

  const config = loadConfig()
  const [owner] = repo.split('/')
  const [issues, labelColors] = await Promise.all([
    fetchAllIssues(repo, token, owner),
    fetchLabels(repo, token),
  ])

  const posts = issues
    .filter((i) => (i.labels || []).length >= 1)
    .map((issue) => buildPostRecord(issue, config, labelColors))

  writeSiteAndPosts(config, posts, labelColors, repo)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
