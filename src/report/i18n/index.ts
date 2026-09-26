import { de } from './de.js'
import { en } from './en.js'
import { LANGUAGES, type Language, type Strings } from './strings.js'

export type { Language, Strings }
export { LANGUAGES }

const LOCALES: Record<Language, Strings> = { en, de }

export function isLanguage(value: string | undefined): value is Language {
  return LANGUAGES.includes(value as Language)
}

/**
 * The strings for a language. English is the default and the fallback, because
 * it is the language every string is written in first — a locale that fell back
 * key by key would produce a half-translated report, which reads worse than an
 * untranslated one.
 */
export function strings(language: Language = 'en'): Strings {
  return LOCALES[language]
}
