/**
 * The local generator: the app's modes, its character sets, its strength figures, and draws
 * without modulo bias.
 */

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { inspect } from 'node:util'
import { describe, it } from 'node:test'

import { EFF_LARGE_WORDLIST_TEXT } from '../src/eff-wordlist.js'
import { InvalidArgumentError } from '../src/errors.js'
import {
  PASSPHRASE_SEPARATORS,
  PASSWORD_SYMBOLS,
  generatePassphrase,
  generatePassword,
  generatePin,
  passphraseBits,
  strengthOf,
} from '../src/generate.js'

// The EFF publishes this digest's file; the generator must draw from exactly that list.
const EFF_SHA256 = 'addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e'

const words = EFF_LARGE_WORDLIST_TEXT.trim()
  .split('\n')
  .map((line) => line.split('\t')[1]!)

describe('the word list', () => {
  it("is the EFF's, byte for byte, and the embedded copy is the file", () => {
    assert.equal(createHash('sha256').update(EFF_LARGE_WORDLIST_TEXT, 'utf8').digest('hex'), EFF_SHA256)
    const file = readFileSync(new URL('../src/eff_large_wordlist.txt', import.meta.url))
    assert.equal(createHash('sha256').update(file).digest('hex'), EFF_SHA256)
    assert.equal(words.length, 7776)
    assert.equal(words[0], 'abacus')
    assert.equal(words[7775], 'zoom')
  })
})

describe('strength', () => {
  // The same table is asserted in all four SDKs, and matches the app and the CLI.
  const table: Array<[string, number, string, string]> = [
    ['password 20, all four sets (94)', 20 * Math.log2(94), '131.0918', 'Very Strong'],
    ['password 8, lowercase only (26)', 8 * Math.log2(26), '37.6035', 'Weak'],
    ['password 12, letters and numbers (62)', 12 * Math.log2(62), '71.4504', 'Strong'],
    ['password 10, numbers and symbols (42)', 10 * Math.log2(42), '53.9232', 'Fair'],
    ['passphrase 5 words', passphraseBits(7776, 5, false), '64.6241', 'Strong'],
    ['passphrase 3 words', passphraseBits(7776, 3, false), '38.7744', 'Weak'],
    ['passphrase 4 words with a digit', passphraseBits(7776, 4, true), '57.0212', 'Fair'],
    ['passphrase 7 words', passphraseBits(7776, 7, false), '90.4737', 'Very Strong'],
    ['pin 6', 6 * Math.log2(10), '19.9316', 'Weak'],
    ['pin 12', 12 * Math.log2(10), '39.8631', 'Weak'],
  ]
  for (const [name, bits, figure, label] of table) {
    it(name, () => {
      assert.equal(bits.toFixed(4), figure)
      assert.equal(strengthOf(bits), label)
    })
  }
})

describe('passwords', () => {
  it("defaults to the app's 20 characters from 94", () => {
    const g = generatePassword()
    assert.equal(g.value.length, 20)
    assert.equal(g.strength, 'Very Strong')
    assert.ok(Math.abs(g.bits - 20 * Math.log2(94)) < 1e-9)
    const pool =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' + PASSWORD_SYMBOLS
    assert.equal(pool.length, 94)
    for (const c of g.value) assert.ok(pool.includes(c), `${c} is outside the pool`)
  })

  it('shapes its pool from the options', () => {
    const g = generatePassword({ length: 64, uppercase: false, symbols: false, exclude: '0123abc' })
    for (const c of g.value) {
      assert.ok(!/[A-Z]/.test(c) && !(PASSWORD_SYMBOLS + '0123abc').includes(c), c)
    }
    // 26 lower + 10 digits, less the 7 excluded.
    assert.ok(Math.abs(g.bits - 64 * Math.log2(29)) < 1e-9)
  })

  it('refuses options out of range rather than adjusting them', () => {
    for (const options of [
      { length: 7 },
      { length: 129 },
      { length: 12.5 },
      { uppercase: false, lowercase: false, numbers: false, symbols: false },
      { uppercase: false, lowercase: false, symbols: false, exclude: '0123456789' },
    ]) {
      assert.throws(() => generatePassword(options), InvalidArgumentError)
    }
  })
})

describe('passphrases', () => {
  it('defaults to five hyphenated words from the list', () => {
    const g = generatePassphrase()
    // Four EFF words carry a hyphen of their own (drop-down, felt-tip, t-shirt, yo-yo), so a
    // hyphenated passphrase can split into more than five parts, never fewer.
    assert.ok(g.value.split('-').length >= 5, g.value)
    assert.equal(g.strength, 'Strong')
    const known = new Set(words)
    for (const w of generatePassphrase({ words: 12, separator: 'space' }).value.split(' ')) {
      assert.ok(known.has(w), `${w} is not on the list`)
    }
  })

  it('honours separator, capitals and a digit', () => {
    const g = generatePassphrase({ words: 4, separator: 'space', capitalize: true, includeNumber: true })
    for (const w of g.value.split(' ')) assert.match(w, /^[A-Z]/)
    assert.equal(g.value.replace(/[^0-9]/g, '').length, 1)
    assert.equal(g.strength, 'Fair')
    for (const [name, sep] of Object.entries(PASSPHRASE_SEPARATORS)) {
      const value = generatePassphrase({ words: 3, separator: name as never }).value
      if (sep) assert.ok(value.split(sep).length >= 3, `${name}: ${value}`)
    }
  })

  it('refuses options out of range', () => {
    for (const options of [{ words: 2 }, { words: 13 }, { separator: 'comma' as never }]) {
      assert.throws(() => generatePassphrase(options), InvalidArgumentError)
    }
  })
})

describe('PINs', () => {
  it('defaults to six digits and refuses out of range', () => {
    const g = generatePin()
    assert.match(g.value, /^\d{6}$/)
    assert.equal(g.strength, 'Weak')
    for (const length of [3, 13, -2]) {
      assert.throws(() => generatePin({ length }), InvalidArgumentError)
    }
  })

  it('draws uniformly', () => {
    // A % reduction of random values would skew this. 60,000 digits: each should come up about
    // 6,000 times, and 20% either way is far outside what chance produces at this size.
    const counts = new Map<string, number>()
    for (let i = 0; i < 5000; i++) {
      for (const d of generatePin({ length: 12 }).value) counts.set(d, (counts.get(d) ?? 0) + 1)
    }
    for (const d of '0123456789') {
      const n = counts.get(d) ?? 0
      assert.ok(n > 4800 && n < 7200, `digit ${d} came up ${n} times in 60,000`)
    }
  })
})

describe('a generated value', () => {
  it('is withheld from printing and from JSON', () => {
    const g = generatePassword()
    for (const rendered of [String(g), JSON.stringify(g), inspect(g)]) {
      assert.ok(!rendered.includes(g.value), rendered)
    }
    assert.equal(typeof g.value, 'string')
  })
})
