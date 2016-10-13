var typeforce = require('typeforce')

var UINT31_MAX = Math.pow(2, 31) - 1
function UInt31 (value) {
  return typeforce.UInt32(value) && value <= UINT31_MAX
}

function BIP32Path (value) {
  return typeforce.String(value) && value.match(/^(m\/)?(\d+'?\/)*\d+'?$/)
}
BIP32Path.toJSON = function () { return 'BIP32 derivation path' }

var SATOSHI_MAX = 2.1 * 1e15
function Satoshi (value) {
  return typeforce.UInt53(value) && value <= SATOSHI_MAX
}

var EC_ZERO = new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
var EC_UINT_MAX = new Buffer('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')

function UInt256 (value) {
  return Buffer.isBuffer(value) &&
    value.length === 32 &&
    value.compare(EC_ZERO) > 0 && // > 0
    value.compare(EC_UINT_MAX) < 0 // < n-1
}

function ECPointB (value) {
  if (!Buffer.isBuffer(value)) return false
  if (value.length < 33) return false

  switch (value[0]) {
    case 0x02:
    case 0x03:
      return value.length === 33
    case 0x04:
      return value.length === 65
  }

  return false
}

// external dependent types
var BigInt = typeforce.quacksLike('BigInteger')
var ECPoint = typeforce.quacksLike('Point')

// exposed, external API
var ECSignature = typeforce.compile({ r: BigInt, s: BigInt })
var Network = typeforce.compile({
  messagePrefix: typeforce.oneOf(typeforce.Buffer, typeforce.String),
  bip32: {
    public: typeforce.UInt32,
    private: typeforce.UInt32
  },
  pubKeyHash: typeforce.UInt8,
  scriptHash: typeforce.UInt8,
  wif: typeforce.UInt8,
  dustThreshold: Satoshi
})

// extend typeforce types with ours
var types = {
  BigInt: BigInt,
  BIP32Path: BIP32Path,
  Buffer256bit: typeforce.BufferN(32),
  ECPoint: ECPoint,
  ECPointB: ECPointB,
  ECSignature: ECSignature,
  Hash160bit: typeforce.BufferN(20),
  Hash256bit: typeforce.BufferN(32),
  Network: Network,
  Satoshi: Satoshi,
  UInt31: UInt31,
  UInt256: UInt256
}

for (var typeName in typeforce) {
  types[typeName] = typeforce[typeName]
}

module.exports = types
