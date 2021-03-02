module.exports = {
  // SERVERS
  protos: ['tcp'],
  host: '127.0.0.1',
  port: 1883,
  wsPort: 3000,
  wssPort: 4000,
  tlsPort: 8883,
  key: null,
  cert: null,
  rejectUnauthorized: true,
  // AUTHORIZER
  authorizer: {
    type: './authorizer',
    credentials: './credentials.json'
  },
  // AEDES
  brokerId: 'aedes-cli',
  concurrency: 100,
  queueLimit: 42,
  maxClientsIdLength: 23,
  heartbeatInterval: 60000,
  connectTimeout: 30000,
  stats: true,
  statsInterval: 5000,
  // PERSISTENCES
  persistence: null,
  mq: null,
  // LOGGER
  verbose: true,
  veryVerbose: false,
  noPretty: false
}
