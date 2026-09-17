import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const dist = path.resolve(fileURLToPath(new URL('.', import.meta.url)), '../dist')
const index = path.join(dist, 'index.html')
const fallback = path.join(dist, '404.html')
if (fs.existsSync(index)) {
  fs.copyFileSync(index, fallback)
  console.log('Wrote SPA fallback 404.html')
}
