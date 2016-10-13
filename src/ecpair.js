var baddress = require('./address')
var bcrypto = require('./crypto')
var ecdsa = require('./ecdsa')
var randomBytes = require('randombytes')
var typeforce = require('typeforce')
var types = require('./types')
var wif = require('wif')

var NETWORKS = require('./networks')
var BigInteger = require('bigi')

var ecurve = require('ecurve')
var secp256k1 = ecdsa.__curve

function ECPair (d, Q, options) {
  if (options) {
    typeforce({
      compressed: types.maybe(types.Boolean),
      network: types.maybe(types.Network)
    }, options)
  }

  if (d) {
    this.d = d
  } else {
    this.__Q = Q
  }

  options = options || {}
  this.compressed = options.compressed === undefined ? true : options.compressed
  this.network = options.network || NETWORKS.bitcoin
}

Object.defineProperty(ECPair.prototype, 'Q', {
  get: function () {
    if (!this.__Q && this.d) {
      this.__Q = secp256k1.G.multiply(this.d)
    }

    return this.__Q
  }
})

// XXX: internal use only
function __fromPrivateKeyInteger (d, options) {
  if (d.signum() <= 0) throw new Error('Private key must be greater than 0')
  if (d.compareTo(secp256k1.n) >= 0) throw new Error('Private key must be less than the curve order')

  return new ECPair(d, null, options)
}

// XXX: internal use only
function __fromPublicKeyPoint (Q, options) {
  return new ECPair(null, Q, options)
}

function fromPrivateKeyBuffer (buffer, options) {
  typeforce(types.UInt256, buffer)
  var d = BigInteger.fromBuffer(d)

  return new ECPair(d, null, options)
}

function fromPublicKeyBuffer (buffer, network) {
  typeforce(types.ECPoint, Q)
  var Q = ecurve.Point.decodeFrom(secp256k1, buffer)

  return new ECPair(null, Q, {
    compressed: Q.compressed,
    network: network
  })
}

function fromWIF (string, network) {
  var decoded = wif.decode(string)
  var version = decoded.version

  // [network, ...]
  if (types.Array(network)) {
    network = network.filter(function (network) {
      return version === network.wif
    }).pop()

    if (!network) throw new Error('Unknown network version')

  // network
  } else {
    network = network || NETWORKS.bitcoin

    if (version !== network.wif) throw new Error('Invalid network version')
  }

  return fromPrivateKeyBuffer(decoded.privateKey, {
    compressed: decoded.compressed,
    network: network
  })
}

function makeRandom (options) {
  options = options || {}

  var rng = options.rng || randomBytes
  var buffer
  do {
    buffer = rng(32)
  } while (!types.UInt256(buffer))

  return fromPrivateKeyBuffer(buffer, options)
}

ECPair.prototype.getAddress = function () {
  return baddress.toBase58Check(bcrypto.hash160(this.getPublicKeyBuffer()), this.getNetwork().pubKeyHash)
}

ECPair.prototype.getNetwork = function () {
  return this.network
}

ECPair.prototype.getPublicKeyBuffer = function () {
  return this.Q.getEncoded(this.compressed)
}

ECPair.prototype.neutered = function () {
  return __fromPublicKeyPoint(this.Q, {
    compressed: this.compressed,
    network: this.network
  })
}

ECPair.prototype.sign = function (hash) {
  if (!this.d) throw new Error('Missing private key')

  return ecdsa.sign(hash, this.d)
}

ECPair.prototype.toWIF = function () {
  if (!this.d) throw new Error('Missing private key')

  return wif.encode(this.network.wif, this.d.toBuffer(32), this.compressed)
}

ECPair.prototype.verify = function (hash, signature) {
  return ecdsa.verify(hash, signature, this.Q)
}

module.exports = {
  fromPrivateKeyBuffer: fromPrivateKeyBuffer,
  fromPublicKeyBuffer: fromPublicKeyBuffer,
  fromWIF: fromWIF,
  makeRandom: makeRandom,

  // XXX: internal use only
  __fromPrivateKeyInteger: __fromPrivateKeyInteger,
  __fromPublicKeyPoint: __fromPublicKeyPoint
}
