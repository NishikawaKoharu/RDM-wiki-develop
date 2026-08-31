#!/usr/bin/env node

const WebSocket = require('ws')
const http = require('http')
const number = require('lib0/number')
const wss = new WebSocket.Server({ noServer: true })
const setupWSConnection = require('./bin/utils.cjs').setupWSConnection
const { authorizeUpgrade, isAuthEnabled } = require('./auth.cjs')

const host = process.env.HOST || 'localhost'
const port = number.parseInt(process.env.PORT || '1234')

const server = http.createServer((_request, response) => {
  response.writeHead(200, { 'Content-Type': 'text/plain' })
  response.end('okay')
})

wss.on('connection', setupWSConnection)

server.on('upgrade', (request, socket, head) => {
  const authResult = authorizeUpgrade(request)
  if (!authResult.authorized) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
    socket.destroy()
    return
  }

  wss.handleUpgrade(request, socket, head, /** @param {any} ws */ ws => {
    wss.emit('connection', ws, request)
  })
})

server.listen(port, host, () => {
  if (isAuthEnabled()) {
    console.log(`running at '${host}' on port ${port} with auth enabled`)
  } else {
    console.log(`running at '${host}' on port ${port} (auth disabled: Y_WEBSOCKET_SECRET is not set)`)
  }
})
