import { defineConfig, type Plugin, type ViteDevServer } from 'vite'
import vue from '@vitejs/plugin-vue'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(fileURLToPath(new URL('.', import.meta.url)), '..')
const dataDir = path.join(root, 'data')

function serveDataPlugin(): Plugin {
  return {
    name: 'serve-repo-data',
    configureServer(server: ViteDevServer) {
      server.middlewares.use('/data', (req, res, next) => {
        try {
          const urlPath = decodeURIComponent((req.url || '/').split('?')[0])
          const filePath = path.join(dataDir, urlPath)
          if (
            !filePath.startsWith(dataDir) ||
            !fs.existsSync(filePath) ||
            !fs.statSync(filePath).isFile()
          ) {
            res.statusCode = 404
            res.end('Not found')
            return
          }
          res.setHeader('Content-Type', 'application/json; charset=utf-8')
          fs.createReadStream(filePath).pipe(res)
        } catch {
          next()
        }
      })
    },
  }
}

export default defineConfig({
  plugins: [vue(), serveDataPlugin()],
  base: '/',
  publicDir: 'public',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
