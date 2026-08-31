const crypto = require('crypto')
const url = require('url')

const Y_WEBSOCKET_SECRET = process.env.Y_WEBSOCKET_SECRET || ''
const Y_WEBSOCKET_ALLOWED_ORIGINS = (process.env.Y_WEBSOCKET_ALLOWED_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean)

function base64UrlDecode (str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/')
  while (str.length % 4) {
    str += '='
  }
  return Buffer.from(str, 'base64')
}

function verifyJwt (token, secret) {
  const parts = token.split('.')
  if (parts.length !== 3) {
    return null
  }

  const [headerB64, payloadB64, signatureB64] = parts
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

  if (signatureB64 !== expectedSignature) {
    return null
  }

  try {
    const payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'))
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null
    }
    return payload
  } catch (error) {
    return null
  }
}

function isOriginAllowed (origin) {
  if (Y_WEBSOCKET_ALLOWED_ORIGINS.length === 0) {
    return true
  }
  if (!origin) {
    return false
  }
  return Y_WEBSOCKET_ALLOWED_ORIGINS.includes(origin)
}

function getDocIdFromRequest (request) {
  const parsedUrl = url.parse(request.url || '', true)
  const pathname = parsedUrl.pathname || ''
  const docId = pathname.replace(/^\/+/, '').split('/')[0]
  return docId || null
}

function getTokenFromRequest (request) {
  const parsedUrl = url.parse(request.url || '', true)
  return parsedUrl.query.token || null
}

function isAuthEnabled () {
  return Boolean(Y_WEBSOCKET_SECRET)
}

function authorizeUpgrade (request) {
  if (!isAuthEnabled()) {
    return { authorized: true }
  }

  const origin = request.headers.origin
  if (!isOriginAllowed(origin)) {
    return { authorized: false, reason: 'origin not allowed' }
  }

  const docId = getDocIdFromRequest(request)
  const token = getTokenFromRequest(request)
  if (!docId || !token) {
    return { authorized: false, reason: 'missing doc id or token' }
  }

  const payload = verifyJwt(token, Y_WEBSOCKET_SECRET)
  if (!payload) {
    return { authorized: false, reason: 'invalid token' }
  }

  if (payload.doc_id !== docId) {
    return { authorized: false, reason: 'doc id mismatch' }
  }

  return { authorized: true, docId }
}

module.exports = {
  authorizeUpgrade,
  isAuthEnabled,
  verifyJwt,
  isOriginAllowed,
  getDocIdFromRequest,
  getTokenFromRequest
}
