#!/usr/bin/env node
// Standalone fallback: an OpenAI-compatible proxy on 127.0.0.1 for the same
// adapter, for when you would rather add Amazon Quick to magpie as a custom
// provider (magpie provider add … --base-url http://127.0.0.1:PORT/v1) than
// load the plugin, or use it from any other OpenAI-compatible client.
//
//   node bin/serve.mjs                  # boots the Quick outpost lazily on first request
//   PORT=3426  HOST=127.0.0.1
//   PROXY_TOKEN=…                       # require "Authorization: Bearer <PROXY_TOKEN>" (recommended)
//   QUICK_AGENT_PATH=…                  # explicit quickwork-agent(.exe)
//   QUICK_AGENT_ZIP=…                   # explicit resources/agent.zip to extract
//   QUICK_SESSION_REUSE=0               # send every request on a fresh Quick thread
//   QUICK_SESSION_TTL_MS=1800000  QUICK_SESSION_MAX=200
import { createServer } from 'node:http'
import { createHash, timingSafeEqual } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { handleChatCompletions, handleModels } from '../lib/handler.mjs'
import { createOutpostManager } from '../lib/outpost.mjs'
import { createSessionStore, SESSION_DEFAULTS } from '../lib/sessions.mjs'

const MAX_BODY_BYTES = 10 * 1024 * 1024
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1'])

function tokenMatch(a, b) {
  const ha = createHash('sha256').update(String(a)).digest()
  const hb = createHash('sha256').update(String(b)).digest()
  return timingSafeEqual(ha, hb)
}

export function createProxyServer({ options = {}, token = '', outpostMgr, sessions } = {}) {
  return createServer(async (req, res) => {
    try {
      if (req.headers.origin) {
        res.writeHead(403, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ error: { message: 'cross-origin browser requests are not allowed', type: 'authentication_error' } }))
      }
      const url = new URL(req.url, 'http://local')
      const path = url.pathname.replace(/\/+$/, '')
      if (token) {
        const got = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || req.headers['x-api-key'] || ''
        if (!got || !tokenMatch(got, token)) {
          res.writeHead(401, { 'content-type': 'application/json' })
          return res.end(JSON.stringify({ error: { message: 'bad proxy token', type: 'authentication_error' } }))
        }
      }
      if (req.method === 'GET' && (path === '/health' || path === '')) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ ok: true }))
      }
      const ac = new AbortController()
      res.on('close', () => { if (!res.writableEnded) ac.abort() })
      let out
      if (req.method === 'GET' && /\/models$/.test(path)) out = handleModels()
      else if (req.method === 'POST' && /\/chat\/completions$/.test(path)) {
        const ct = req.headers['content-type']
        if (ct && !/\bapplication\/json\b/i.test(String(ct))) {
          res.writeHead(415, { 'content-type': 'application/json' })
          return res.end(JSON.stringify({ error: { message: 'content-type must be application/json', type: 'invalid_request_error' } }))
        }
        const chunks = []
        let total = 0
        for await (const c of req) {
          const buf = typeof c === 'string' ? Buffer.from(c) : c
          total += buf.length
          if (total > MAX_BODY_BYTES) {
            req.destroy()
            res.writeHead(413, { 'content-type': 'application/json' })
            return res.end(JSON.stringify({ error: { message: 'request body too large', type: 'invalid_request_error' } }))
          }
          chunks.push(buf)
        }
        const raw = Buffer.concat(chunks).toString('utf8')
        let body
        try { body = JSON.parse(raw || '{}') } catch {
          res.writeHead(400, { 'content-type': 'application/json' })
          return res.end(JSON.stringify({ error: { message: 'request body must be JSON', type: 'invalid_request_error' } }))
        }
        out = await handleChatCompletions({ body, outpostMgr, options, signal: ac.signal, sessions })
      } else {
        res.writeHead(404, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ error: { message: `not found: ${req.method} ${path}`, type: 'invalid_request_error' } }))
      }
      res.writeHead(out.status, Object.fromEntries(out.headers))
      if (!out.body) return res.end()
      for await (const chunk of out.body) res.write(chunk)
      res.end()
    } catch (e) {
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: { message: String(e?.message ?? e), type: 'api_error' } }))
    }
  })
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (isMain) {
  const port = Number(process.env.PORT || 3426)
  const host = process.env.HOST || '127.0.0.1'
  const options = {}
  if (process.env.QUICK_AGENT_PATH) options.agentPath = process.env.QUICK_AGENT_PATH
  if (process.env.QUICK_AGENT_ZIP) options.agentZip = process.env.QUICK_AGENT_ZIP
  if (process.env.QUICK_USER_DATA_DIR) options.userDataDir = process.env.QUICK_USER_DATA_DIR
  if (process.env.QUICK_CACHE_DIR) options.cacheDir = process.env.QUICK_CACHE_DIR
  if (process.env.QUICK_OUTPOST_PORT) options.port = Number(process.env.QUICK_OUTPOST_PORT)
  if (process.env.QUICK_BUILD_STAGE) options.buildStage = process.env.QUICK_BUILD_STAGE
  const reuse = !/^(0|false|off|no)$/i.test(process.env.QUICK_SESSION_REUSE ?? '')
  const sessions = reuse
    ? createSessionStore({
        ttlMs: Number(process.env.QUICK_SESSION_TTL_MS) > 0 ? Number(process.env.QUICK_SESSION_TTL_MS) : SESSION_DEFAULTS.ttlMs,
        max: Number(process.env.QUICK_SESSION_MAX) > 0 ? Number(process.env.QUICK_SESSION_MAX) : SESSION_DEFAULTS.max,
      })
    : undefined
  const proxyToken = process.env.PROXY_TOKEN || ''
  if (!proxyToken && !LOOPBACK_HOSTS.has(host.toLowerCase())) {
    console.error('Refusing to bind non-loopback HOST without PROXY_TOKEN set.')
    process.exit(1)
  }
  if (!proxyToken) console.error('[warn] PROXY_TOKEN is not set; local proxy is unauthenticated')
  const outpostMgr = createOutpostManager({ ...options, log: (l) => console.error('[outpost]', l) })
  createProxyServer({ options: { ...options, identity: 'aws-quick-proxy' }, token: proxyToken, outpostMgr, sessions }).listen(port, host, () => {
    console.error(`aws-quick proxy listening on http://${host}:${port}/v1 (outpost starts on first request)`)
  })
}
