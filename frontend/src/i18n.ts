import i18n from "i18next";
import { initReactI18next } from "react-i18next";

export const SUPPORTED_LOCALES = ["en-US", "zh-CN", "he"] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

export const DEFAULT_LOCALE: SupportedLocale = SUPPORTED_LOCALES[0];
const RTL_LOCALES = new Set<SupportedLocale>(["he"]);
const LOCALE_STORAGE_KEY = "ztix.locale";

export const LOCALE_OPTIONS: ReadonlyArray<{ code: SupportedLocale; flag: string }> = [
  { code: "en-US", flag: "\ud83c\uddfa\ud83c\uddf8" },
  { code: "zh-CN", flag: "\ud83c\udde8\ud83c\uddf3" },
  { code: "he", flag: "\ud83c\uddee\ud83c\uddf1" },
];

let initializePromise: Promise<void> | null = null;

function applyDocumentLocale(locale: SupportedLocale): void {
  document.documentElement.lang = locale;
  document.documentElement.dir = RTL_LOCALES.has(locale) ? "rtl" : "ltr";
}

function normalizeLanguageTag(languageTag: string): string {
  return languageTag.trim().toLowerCase();
}

export function resolveSupportedLocale(locale: string | null | undefined): SupportedLocale | undefined {
  if (!locale) {
    return undefined;
  }

  const normalized = normalizeLanguageTag(locale);
  const exactMatch = SUPPORTED_LOCALES.find((candidate) => normalizeLanguageTag(candidate) === normalized);
  if (exactMatch) {
    return exactMatch;
  }

  const base = normalized.split("-")[0];
  return SUPPORTED_LOCALES.find((candidate) => normalizeLanguageTag(candidate).split("-")[0] === base);
}

function readStoredLocale(): SupportedLocale | undefined {
  try {
    const stored = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    return resolveSupportedLocale(stored);
  } catch {
    return undefined;
  }
}

function detectPreferredLocale(): SupportedLocale {
  for (const language of navigator.languages) {
    const matched = resolveSupportedLocale(language);
    if (matched) {
      return matched;
    }
  }

  const singleLanguageMatch = resolveSupportedLocale(navigator.language);
  return singleLanguageMatch ?? DEFAULT_LOCALE;
}

async function loadLocaleCatalog(locale: SupportedLocale): Promise<Record<string, unknown>> {
  const response = await fetch(`${import.meta.env.BASE_URL}locales/${locale}/common.json`);
  if (!response.ok) {
    throw new Error(`failed to load locale catalog: ${locale}`);
  }

  const parsed = (await response.json()) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error(`invalid locale catalog payload: ${locale}`);
  }

  return parsed as Record<string, unknown>;
}

async function loadResources(): Promise<Record<string, { translation: Record<string, unknown> }>> {
  const fallbackCatalog = await loadLocaleCatalog(DEFAULT_LOCALE);
  const entries = await Promise.all(
    SUPPORTED_LOCALES.map(async (locale) => {
      if (locale === DEFAULT_LOCALE) {
        return [locale, { translation: fallbackCatalog }] as const;
      }

      let catalog = fallbackCatalog;
      try {
        catalog = await loadLocaleCatalog(locale);
      } catch {
        // Keep locale available with fallback content when catalog fetch fails.
      }

      return [locale, { translation: catalog }] as const;
    }),
  );

  return Object.fromEntries(entries);
}

export async function initializeI18n(): Promise<void> {
  if (!initializePromise) {
    initializePromise = (async () => {
      const resources = await loadResources();
      const initialLocale = readStoredLocale() ?? detectPreferredLocale();

      await i18n.use(initReactI18next).init({
        resources,
        lng: initialLocale,
        fallbackLng: DEFAULT_LOCALE,
        supportedLngs: [...SUPPORTED_LOCALES],
        interpolation: {
          escapeValue: false,
        },
        returnNull: false,
      });

      applyDocumentLocale(initialLocale);
      i18n.on("languageChanged", (nextLanguage) => {
        const resolved = resolveSupportedLocale(nextLanguage) ?? DEFAULT_LOCALE;
        try {
          window.localStorage.setItem(LOCALE_STORAGE_KEY, resolved);
        } catch {
          // Ignore storage failures and keep in-memory language state.
        }
        applyDocumentLocale(resolved);
      });
    })();
  }

  return initializePromise;
}
