(() => {
  let mode = "system";
  try {
    const stored = localStorage.getItem("aienv.theme");
    if (stored === "light" || stored === "dark") mode = stored;
  } catch {}
  const resolved = mode === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : mode;
  document.documentElement.classList.toggle("dark", resolved === "dark");
  document.documentElement.style.colorScheme = resolved;
  document.documentElement.dataset.theme = resolved;
})();
