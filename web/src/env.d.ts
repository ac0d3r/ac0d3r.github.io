/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DATA_BASE?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
