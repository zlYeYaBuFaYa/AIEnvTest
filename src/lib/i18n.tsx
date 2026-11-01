import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import en from "../../locales/en.json";
import zh from "../../locales/zh-CN.json";
import ja from "../../locales/ja.json";
import ko from "../../locales/ko.json";
import type { Lang } from "./types";

const catalogs: Record<Lang, Record<string, string>> = {
  en,
  "zh-CN": zh,
  ja,
  ko,
};

type I18nValue = {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (key: string, params?: Record<string, string>) => string;
};

const I18nContext = createContext<I18nValue | null>(null);

function apply(template: string, params?: Record<string, string>) {
  if (!params) return template;
  return Object.entries(params).reduce((text, [key, value]) => text.replaceAll(`{${key}}`, value), template);
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    const stored = localStorage.getItem("aienv.lang");
    if (stored === "en" || stored === "zh-CN" || stored === "ja" || stored === "ko") return stored;
    return "en";
  });

  const value = useMemo<I18nValue>(() => {
    const setLang = (next: Lang) => {
      localStorage.setItem("aienv.lang", next);
      setLangState(next);
    };
    const t = (key: string, params?: Record<string, string>) => {
      const template = catalogs[lang][key] ?? catalogs.en[key] ?? key;
      return apply(template, params);
    };
    return { lang, setLang, t };
  }, [lang]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const value = useContext(I18nContext);
  if (!value) throw new Error("useI18n outside provider");
  return value;
}
