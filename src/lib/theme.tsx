import { getCurrentWindow } from "@tauri-apps/api/window";
import { createContext, useContext, useLayoutEffect, useMemo, useState, type ReactNode } from "react";

export type ThemeMode = "light" | "dark" | "system";
type ResolvedTheme = "light" | "dark";
type ThemeValue = { mode: ThemeMode; setMode: (mode: ThemeMode) => void; resolved: ResolvedTheme };
const ThemeContext = createContext<ThemeValue | null>(null);
const query = "(prefers-color-scheme: dark)";

function readMode(): ThemeMode {
  try {
    const stored = localStorage.getItem("aienv.theme");
    if (stored === "light" || stored === "dark") return stored;
  } catch { /* Storage may be unavailable; follow the OS. */ }
  return "system";
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<ThemeMode>(readMode);
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() => window.matchMedia(query).matches ? "dark" : "light");
  const resolved = mode === "system" ? systemTheme : mode;

  useLayoutEffect(() => {
    if (mode !== "system") return;
    const media = window.matchMedia(query);
    const update = () => setSystemTheme(media.matches ? "dark" : "light");
    update();
    if (media.addEventListener) {
      media.addEventListener("change", update);
      return () => media.removeEventListener("change", update);
    }
    media.addListener(update);
    return () => media.removeListener(update);
  }, [mode]);

  useLayoutEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", resolved === "dark");
    root.style.colorScheme = resolved;
    root.dataset.theme = resolved;
    try { localStorage.setItem("aienv.theme", mode); } catch { /* Theme still works without storage. */ }
  }, [mode, resolved]);

  useLayoutEffect(() => {
    if (!("__TAURI_INTERNALS__" in window)) return;
    try {
      getCurrentWindow().setTheme(mode === "system" ? null : mode).catch(() => {});
    } catch { /* Native theming may be unavailable. */ }
  }, [mode]);

  const value = useMemo(() => ({ mode, setMode, resolved }), [mode, resolved]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const value = useContext(ThemeContext);
  if (!value) throw new Error("useTheme outside provider");
  return value;
}
