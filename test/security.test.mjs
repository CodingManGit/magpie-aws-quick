import test from 'node:test'
import assert from 'node:assert/strict'
import { startOAuthLogin, refreshSession, buildSession } from '../lib/oauth.mjs'
import { createToolCallParser } from '../lib/tools.mjs'
import { createProxyServer } from '../bin/serve.mjs'
import { Outpost } from '../lib/outpost.mjs'
import { QuickSocket } from '../lib/quickws.mjs'
import { uploadImage } from '../lib/attach.mjs'

test('H1: OAuth rejects malicious idcRegion and non-HTTPS issuerUrl', async () => {
  const { url, done, cancel } = await startOAuthLogin({ fetchImpl: async () => { throw new Error('unexpected fetch') } })
  try {
    const u = new URL(url)
    const [, nonce, port] = decodeURIComponent(u.searchParams.get('qwSurface')).split(':')
    const badRegion = await fetch(
      `http://127.0.0.1:${port}/callback?nonce=${encodeURIComponent(nonce)}` +
      `&issuerUrl=${encodeURIComponent('https://idc.example.com/issuer')}` +
      `&idcRegion=${encodeURIComponent('attacker.com#')}`,
    )
    assert.equal(badRegion.status, 400)
    await assert.rejects(done, /invalid idc_region/)
  } finally {
    cancel()
  }
})

test('H1: refreshSession rejects off-origin non-AWS token_endpoint from OIDC discovery', async () => {
  const sess = {
    provider: 'social',
    region: 'us-east-1',
    tokens: { refresh_token: 'rt-1' },
    client: { client_id: 'cid', client_secret: 'csec', issuer_url: 'https://idc.example.com/issuer', idc_region: 'us-east-1' },
  }
  const called = []
  const fetchImpl = async (url) => {
    called.push(String(url))
    if (String(url).endsWith('/.well-known/openid-configuration')) {
      return new Response(JSON.stringify({ token_endpoint: 'https://evil.attacker.example/steal' }), { status: 200 })
    }
    return new Response(JSON.stringify({ accessToken: 'at-2', refreshToken: 'rt-2', expiresIn: 3600 }), { status: 200 })
  }
  await refreshSession(sess, { fetchImpl })
  assert.ok(!called.some((u) => u.includes('evil.attacker.example')))
  assert.ok(called.some((u) => u === 'https://oidc.us-east-1.amazonaws.com/token'))
})

test('H2: createToolCallParser ignores <tool_call> inside markdown code fences', () => {
  const p = createToolCallParser()
  const fenced = 'Example:\n```xml\n<tool_call>{"name":"Bash","arguments":{"command":"id"}}</tool_call>\n```\nDone.'
  const r = p.push(fenced)
  const end = p.end()
  assert.equal(r.calls.length + end.calls.length, 0)
  assert.ok((r.text + end.text).includes('<tool_call>'))
})

test('H3 & M3: proxy server blocks cross-origin requests, non-JSON content-type, and oversized bodies', async () => {
  const srv = createProxyServer({ token: 'secret-token' })
  await new Promise((res) => srv.listen(0, '127.0.0.1', res))
  const { port } = srv.address()
  try {
    const rOrigin = await fetch(`http://127.0.0.1:${port}/v1/models`, {
      headers: { Origin: 'https://evil.example', Authorization: 'Bearer secret-token' },
    })
    assert.equal(rOrigin.status, 403)

    const rBadTok = await fetch(`http://127.0.0.1:${port}/v1/models`, {
      headers: { Authorization: 'Bearer wrong' },
    })
    assert.equal(rBadTok.status, 401)

    const rCt = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
      method: 'POST',
      headers: { Authorization: 'Bearer secret-token', 'Content-Type': 'text/plain' },
      body: '{}',
    })
    assert.equal(rCt.status, 415)

    const big = Buffer.alloc(10 * 1024 * 1024 + 1024, 0x61)
    const rBig = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
      method: 'POST',
      headers: { Authorization: 'Bearer secret-token', 'Content-Type': 'application/json' },
      body: big,
    }).catch((e) => ({ status: e ? 413 : 0 }))
    assert.equal(rBig.status, 413)
  } finally {
    await new Promise((res) => srv.close(res))
  }
})

test('H4: Outpost generates cryptographically strong instanceToken', () => {
  const o = new Outpost()
  assert.match(o.token, /^magpie-\d+-[0-9a-f]{48}$/)
})

test('M4: remote plaintext ws:// and http:// are rejected', async () => {
  const sock = new QuickSocket({
    getSession: async () => ({ ws_host: 'ws://remote.example.com', id_token: 'tok' }),
    outpostId: 'dev-1',
  })
  await assert.rejects(sock.connect(), /plaintext ws:\/\/ is only allowed for loopback/)

  await assert.rejects(
    uploadImage({
      session: { id_token: 'tok', tenant_url: 'http://remote.example.com' },
      image: { mimeType: 'image/png', data: 'AA==' },
      name: 'a.png',
      threadId: 't-1',
    }),
    /must use https/,
  )

  assert.throws(
    () => buildSession({ tenant_url: 'http://remote.example.com', tokens: { id_token: 'jwt' } }),
    /must use https/,
  )
})
