/**
 * A local generator for passwords, passphrases and PINs (Gitea #404): the app's three modes and
 * the CLI's, with nothing sent anywhere. A generated secret never leaves this process unless the
 * caller sends it.
 */
import { EFF_LARGE_WORDLIST_TEXT } from './eff-wordlist.js'
import { InvalidArgumentError } from './errors.js'

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
const NUMBERS = '0123456789'

/** The symbols a password may draw from, the app's set. */
export const PASSWORD_SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?`"~/\\\''

/**
 * A generated secret with its strength.
 *
 * A class rather than a plain object for the reason `Share` is one: printing it, logging it or
 * passing it through `JSON.stringify` does not print the secret. `value` is still there, by name.
 */
export class Generated {
  readonly value: string
  /** The entropy of what the options generate, not of this one value. */
  readonly bits: number
  /** `strengthOf(bits)`: Weak, Fair, Strong or Very Strong. */
  readonly strength: string

  constructor(value: string, bits: number) {
    this.value = value
    this.bits = bits
    this.strength = strengthOf(bits)
  }

  /** Redacted. The value is omitted on purpose. */
  toJSON(): Record<string, unknown> {
    return { value: '[redacted]', bits: this.bits, strength: this.strength }
  }

  toString(): string {
    return `Generated(${this.strength}, ${Math.round(this.bits)} bits, value redacted)`
  }

  /** Node's console.log / util.inspect path, which ignores toJSON. */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString()
  }
}

export interface PasswordOptions {
  /** 8 to 128. Defaults to 20. */
  length?: number
  /** Each set is on unless switched off. */
  uppercase?: boolean
  lowercase?: boolean
  numbers?: boolean
  symbols?: boolean
  /** Characters to leave out, such as `0Ol1` for a password read aloud. */
  exclude?: string
}

/** A password drawn uniformly from the chosen characters. The defaults are the app's. */
export function generatePassword(options: PasswordOptions = {}): Generated {
  const length = options.length ?? 20
  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw new InvalidArgumentError(`a password is 8 to 128 characters, got ${length}`)
  }
  const excluded = new Set(Array.from(options.exclude ?? ''))
  let pool = ''
  if (options.uppercase ?? true) pool += UPPERCASE
  if (options.lowercase ?? true) pool += LOWERCASE
  if (options.numbers ?? true) pool += NUMBERS
  if (options.symbols ?? true) pool += PASSWORD_SYMBOLS
  const chars = Array.from(pool).filter((c) => !excluded.has(c))
  if (chars.length === 0) {
    throw new InvalidArgumentError('those options leave no characters to choose from')
  }
  return new Generated(randomFrom(chars, length), length * Math.log2(chars.length))
}

/** The separators by the names the app and the CLI use. */
export const PASSPHRASE_SEPARATORS = {
  hyphen: '-',
  space: ' ',
  period: '.',
  underscore: '_',
  none: '',
} as const

export type PassphraseSeparator = keyof typeof PASSPHRASE_SEPARATORS

export interface PassphraseOptions {
  /** 3 to 12. Defaults to 5. */
  words?: number
  /** Defaults to `hyphen`. */
  separator?: PassphraseSeparator
  /**
   * Upper-case each word's first letter. It changes the look, not the strength: every word
   * gets one, so it is not random.
   */
  capitalize?: boolean
  /** Append one random digit to one random word. */
  includeNumber?: boolean
}

let words: readonly string[] | null = null

/** The EFF long word list, 7,776 words, parsed once on first use. */
function wordList(): readonly string[] {
  words ??= EFF_LARGE_WORDLIST_TEXT.trim()
    .split('\n')
    .map((line) => line.trim().split('\t')[1])
    .filter((word): word is string => Boolean(word))
  return words
}

/** A passphrase drawn uniformly from the EFF long word list (12.9 bits a word). */
export function generatePassphrase(options: PassphraseOptions = {}): Generated {
  const n = options.words ?? 5
  if (!Number.isInteger(n) || n < 3 || n > 12) {
    throw new InvalidArgumentError(`a passphrase is 3 to 12 words, got ${n}`)
  }
  const name = options.separator ?? 'hyphen'
  if (!Object.prototype.hasOwnProperty.call(PASSPHRASE_SEPARATORS, name)) {
    throw new InvalidArgumentError(
      `separator is hyphen, space, period, underscore or none, not ${JSON.stringify(name)}`,
    )
  }
  const list = wordList()
  const picked = Array.from({ length: n }, () => {
    const word = list[randomBelow(list.length)]!
    return options.capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word
  })
  if (options.includeNumber) {
    const where = randomBelow(n)
    picked[where] = picked[where]! + String(randomBelow(10))
  }
  return new Generated(
    picked.join(PASSPHRASE_SEPARATORS[name]),
    passphraseBits(list.length, n, options.includeNumber ?? false),
  )
}

/**
 * Each word is log2 of the list; the digit adds log2(10) and its position log2(words).
 * Exported for the strength table the tests share with the other SDKs.
 */
export function passphraseBits(listSize: number, n: number, withNumber: boolean): number {
  let bits = n * Math.log2(listSize)
  if (withNumber) bits += Math.log2(10) + Math.log2(n)
  return bits
}

/** A PIN of `length` digits, 4 to 12. Defaults to 6. */
export function generatePin(options: { length?: number } = {}): Generated {
  const length = options.length ?? 6
  if (!Number.isInteger(length) || length < 4 || length > 12) {
    throw new InvalidArgumentError(`a PIN is 4 to 12 digits, got ${length}`)
  }
  return new Generated(randomFrom(Array.from(NUMBERS), length), length * Math.log2(10))
}

/** The app generator's label for a number of bits. */
export function strengthOf(bits: number): 'Weak' | 'Fair' | 'Strong' | 'Very Strong' {
  if (bits < 40) return 'Weak'
  if (bits < 60) return 'Fair'
  if (bits < 80) return 'Strong'
  return 'Very Strong'
}

/**
 * A uniform draw from [0, n), by rejection sampling. Reducing a random 32-bit value with `% n`
 * is biased whenever n does not divide 2^32, and neither 94 nor 7,776 does: the values at or
 * above the last whole multiple of n are drawn again rather than folded back in.
 */
function randomBelow(n: number): number {
  const limit = Math.floor(0x1_0000_0000 / n) * n
  const draw = new Uint32Array(1)
  for (;;) {
    globalThis.crypto.getRandomValues(draw)
    if (draw[0]! < limit) return draw[0]! % n
  }
}

function randomFrom(chars: readonly string[], n: number): string {
  let out = ''
  for (let i = 0; i < n; i++) out += chars[randomBelow(chars.length)]!
  return out
}
