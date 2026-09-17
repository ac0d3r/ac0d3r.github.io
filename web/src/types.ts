export interface SiteConfig {
  title: string
  subTitle: string
  avatarUrl: string
  homeUrl: string
  startSite: string
  filingNum: string
  bottomText: string
  i18n: string
  themeMode: string
  dayTheme: string
  nightTheme: string
  needComment: number
  onePageListNum: number
  singlePage: string[]
  useTimeline: string[]
  exlink: Record<string, string>
  repo: string
  labelColors: Record<string, string>
  generatedAt?: string
}

export interface PostMeta {
  number: number
  title: string
  slug: string
  labels: string[]
  createdAt: number
  createdDate: string
  dateLabelColor: string
  updatedAt: string | null
  excerpt: string
  wordCount: number
  top: number
  singlePage: boolean
  timeline: boolean
  needComment: boolean
  ogImage: string
  labelColors: Record<string, string>
}

export interface Post extends PostMeta {
  body: string
}

export interface PostsIndex {
  posts: PostMeta[]
  pages: PostMeta[]
}
