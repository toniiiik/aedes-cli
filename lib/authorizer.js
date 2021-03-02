'use strict'

const hasher = require('./hasher')
const minimatch = require('minimatch')
const { readFile, writeFile } = require('fs').promises
const defaultGlob = '**'

const mapToObj = m => {
  return Array.from(m).reduce((obj, [key, value]) => {
    obj[key] = value
    return obj
  }, {})
}

// polyfill for Map
Object.entries = typeof Object.entries === 'function' ? Object.entries : obj => Object.keys(obj).map(k => [k, obj[k]])

/**
 * Authorizer's responsibility is to give an implementation
 * of Aedes callback of authorizations, against a JSON file.
 *
 * @param {Object} users The user hash, as created by this class
 *  (optional)
 * @api public
 */
function Authorizer (config) {
  this.users = null
  this.config = config
  this.isInitialized = false
}
module.exports = Authorizer

/**
 * Save actual user state to credential file
 *
 * @api public
 */
Authorizer.prototype.save = async function () {
  return writeFile(this.config.credentials, JSON.stringify(this.users, null, 2))
}

/**
 * Initialize authorizer. Load users
 *
 * @api public
 */
Authorizer.prototype.init = async function (force) {
  const that = this
  if (that.config.credentials) {
    let data
    try {
      data = await readFile(that.config.credentials)
      data = JSON.parse(data)
    } catch (error) {
      console.log('unable to load credentials file: %s', that.config.credentials, error.message)
      if (force) {
        console.log('creating NEW credentials file %s', that.config.credentials)
        data = {}
      } else {
        return
      }
    }
    that.users = data
  }
}

/**
 * It returns the authenticate function to plug into Aedes.
 *
 * @api public
 */
Authorizer.prototype.authenticate = function () {
  const that = this
  return function (client, user, pass, cb) {
    console.log(`auth: Client=${client} user=${user} password=${pass} `)
    that._authenticate(client, user, pass, cb)
  }
}

/**
 * It returns the authorizePublish function to plug into Aedes.
 *
 * @api public
 */
Authorizer.prototype.authorizePublish = function () {
  const that = this
  return function (client, packet, cb) {
    cb(minimatch(packet.topic, that._users.get(client.user).authorizePublish || defaultGlob) ? null : Error('Publish not authorized'))
  }
}

/**
 * It returns the authorizeSubscribe function to plug into Aedes.
 *
 * @api public
 */
Authorizer.prototype.authorizeSubscribe = function () {
  const that = this
  return function (client, sub, cb) {
    cb(null, minimatch(sub.topic, that._users.get(client.user).authorizeSubscribe || defaultGlob) ? sub : null)
  }
}

/**
 * The real authentication function
 *
 * @api private
 */
Authorizer.prototype._authenticate = function (client, user, pass, cb) {
  const missingUser = !user || !pass || !this._users.get(user)

  if (missingUser) {
    cb(null, false)
    return
  }

  user = user.toString()

  client.user = user
  user = this._users.get(user)

  hasher.verifyPassword(user, pass.toString())
    .then(success => cb(null, success))
    .catch((err) => {
      cb(err)
    })
}

/**
 * An utility function to add an user.
 *
 * @api public
 * @param {String} user The username
 * @param {String} pass The password
 * @param {String} authorizePublish The authorizePublish pattern
 *   (optional)
 * @param {String} authorizeSubscribe The authorizeSubscribe pattern
 *   (optional)
 */
Authorizer.prototype.addUser = async function (user, pass, authorizePublish,
  authorizeSubscribe) {
  if (!authorizePublish) {
    authorizePublish = defaultGlob
  }

  if (!authorizeSubscribe) {
    authorizeSubscribe = defaultGlob
  }

  const { salt, hash } = await hasher.generateHashPassword(pass.toString())

  const exists = this._users.get(user)

  this._users.set(user, {
    salt: salt,
    hash: hash,
    authorizePublish: authorizePublish,
    authorizeSubscribe: authorizeSubscribe
  })

  return exists
}

/**
 * An utility function to delete a user.
 *
 * @api public
 * @param {String} user The username
 */
Authorizer.prototype.rmUser = function (user) {
  const exists = this._users.get(user)
  this._users.delete(user)

  return exists
}

/**
 * Print available options
 */
Authorizer.printOptions = function () {
  console.log('Basic json file authorizer.\n')
  console.log('available options are:\n\tcredentials:\t define path to credentials file')
}

/**
 * Users
 */
Object.defineProperty(Authorizer.prototype, 'users', {
  get: function () {
    return mapToObj(this._users)
  },
  set: function (users) {
    users = users || {}
    this._users = new Map(Object.entries(users))
  },
  enumerable: true
})
