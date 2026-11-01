import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button, StatusBadge } from "@/components/ui";
import { useTheme } from "@/lib/theme";
import { useI18n } from "@/lib/i18n";
import type { CheckResult, Lang, RegionSummary, ScanReport, Status, Verdict } from "@/lib/types";
import { cn } from "@/lib/utils";

const LANGS: { id: Lang; label: string }[] = [
  { id: "en", label: "EN" },
  { id: "zh-CN", label: "中文" },
  { id: "ja", label: "日本語" },
  { id: "ko", label: "한국어" },
];

const GROUPS = ["exit", "routing", "proxy", "dns", "system", "browser", "destination"];
const GROUP_LABEL: Record<string, string> = {
  americas: "group.americas",
  europe: "group.europe",
  asiaPacific: "group.asiaPacific",
};

const STATUSES: Status[] = ["fail", "warn", "inconclusive", "info", "pass"];

export default function App() {
  const { mode, setMode } = useTheme();
  const { lang, setLang, t } = useI18n();
  const [regions, setRegions] = useState<RegionSummary[]>([]);
  const [regionId, setRegionId] = useState("us");
  const [scanning, setScanning] = useState(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  useEffect(() => {
    invoke<RegionSummary[]>("list_regions")
      .then((items) => {
        setRegions(items);
        if (!items.some((item) => item.id === "us") && items[0]) setRegionId(items[0].id);
      })
      .catch((err: unknown) => setError(String(err)));
  }, []);

  const groupedRegions = useMemo(() => {
    const groups = new Map<string, RegionSummary[]>();
    for (const region of regions) {
      const list = groups.get(region.group) ?? [];
      list.push(region);
      groups.set(region.group, list);
    }
    return [...groups.entries()];
  }, [regions]);

  async function scan() {
    setScanning(true);
    setError("");
    setSaved("");
    try {
      const next = await invoke<ScanReport>("run_scan", { regionId });
      setReport(next);
    } catch (err) {
      setError(t("error.scan", { error: String(err) }));
    } finally {
      setScanning(false);
    }
  }

  async function exportReport(kind: "json" | "md") {
    if (!report) return;
    setSaved("");
    try {
      const contents =
        kind === "json" ? JSON.stringify(report, null, 2) : await invoke<string>("render_markdown", { report, lang });
      const stamp = report.generatedAt.slice(0, 19).replace(/[:T]/g, "");
      const fileName = `aienv-${report.regionId}-${stamp}.${kind === "json" ? "json" : "md"}`;
      const path = await invoke<string>("write_export", { fileName, contents });
      setSaved(t("export.saved", { path }));
    } catch (err) {
      setSaved(t("export.failed", { error: String(err) }));
    }
  }

  const counts = useMemo(() => {
    const tally: Record<Status, number> = { pass: 0, warn: 0, fail: 0, info: 0, inconclusive: 0 };
    for (const check of report?.checks ?? []) tally[check.status] += 1;
    return tally;
  }, [report]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-wrap items-end justify-between gap-4 px-6 pb-3 pt-5">
        <div>
          <div className="flex items-center gap-3">
            <span className="grid h-10 w-10 place-items-center rounded-2xl bg-teal text-sm font-semibold tracking-wide text-on-teal">
              Ae
            </span>
            <div>
              <h1 className="font-serif text-3xl leading-none tracking-tight text-ink">
                AI<span className="text-teal">Env</span>
              </h1>
              <p className="mt-1 text-sm text-muted">{t("app.subtitle")}</p>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex rounded-full border border-line bg-card p-1" role="group" aria-label={t("lang.label")}>
            {LANGS.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setLang(item.id)}
                className={cn(
                  "rounded-full px-3 py-1.5 text-sm",
                  lang === item.id ? "bg-ink text-on-ink" : "text-muted hover:text-ink",
                )}
              >
                {item.label}
              </button>
            ))}
          </div>
          <div className="flex rounded-full border border-line bg-card p-1" role="group" aria-label={t("theme.label")}>
            {(["light", "dark", "system"] as const).map((item) => (
              <button key={item} type="button" onClick={() => setMode(item)}
                aria-label={t(`theme.${item}`)} title={t(`theme.${item}`)} aria-pressed={mode === item}
                className={cn("rounded-full p-2", mode === item ? "bg-ink text-on-ink" : "text-muted hover:bg-hover hover:text-ink")}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  {item === "light" ? <><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5" /></> : item === "dark" ? <path d="M21 13a9 9 0 0 1-10-10 9 9 0 1 0 10 10Z" /> : <><rect x="3" y="4" width="18" height="13" rx="2" /><path d="M8 21h8m-4-4v4" /></>}
                </svg>
              </button>
            ))}
          </div>
        </div>
      </header>

      <section className="grid gap-3 px-6 pb-4 md:grid-cols-2" aria-label="notices">
        <Notice tone="info" title={t("notice.purpose.title")} body={t("notice.purpose.body")} />
        <Notice tone="risk" title={t("notice.risk.title")} body={t("notice.risk.body")} />
      </section>

      <section className="mx-6 mb-4 flex flex-col gap-3 rounded-3xl border border-line bg-card/90 p-3 shadow-card md:flex-row md:items-end">
        <label className="min-w-0 flex-1">
          <span className="mb-1 block px-2 text-xs font-semibold uppercase tracking-wide text-muted">{t("region.label")}</span>
          <select
            className="h-11 w-full rounded-2xl border border-line bg-paper px-3 text-sm outline-none focus:ring-2 focus:ring-teal"
            value={regionId}
            onChange={(event) => setRegionId(event.target.value)}
          >
            {groupedRegions.map(([group, items]) => (
              <optgroup key={group} label={t(GROUP_LABEL[group] ?? group)}>
                {items.map((region) => (
                  <option key={region.id} value={region.id}>
                    {region.name[lang] ?? region.name.en} · {region.country}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </label>
        <Button className="md:min-w-36" onClick={scan} disabled={scanning || regions.length === 0}>
          {scanning ? t("scan.running") : report ? t("scan.again") : t("scan.action")}
        </Button>
        <Button variant="outline" size="sm" onClick={() => invoke("reopen_browser").catch((err: unknown) => setError(String(err)))} disabled={!report}>
          {t("browser.reopen")}
        </Button>
      </section>
      <p className="px-8 pb-3 text-sm text-muted">{t("scan.hint")}</p>

      <div className="min-h-0 flex-1 overflow-y-auto px-6 pb-8">
        {error && <p className="mb-3 rounded-2xl border border-status-fail-border/40 bg-status-fail-bg px-4 py-3 text-sm text-status-fail-ink">{error}</p>}
        {!report && !scanning && (
          <div className="rounded-3xl border border-dashed border-line bg-card/70 px-6 py-10">
            <h2 className="font-serif text-2xl">{t("empty.title")}</h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">{t("empty.body")}</p>
          </div>
        )}
        {scanning && <p className="mb-3 text-sm text-teal">{t("browser.waiting")}</p>}
        {report && (
          <div className="grid gap-4 lg:grid-cols-[280px_minmax(0,1fr)]">
            <aside className="h-fit rounded-3xl border border-line bg-card p-4 shadow-card lg:sticky lg:top-0">
              <p className="text-xs font-semibold uppercase tracking-wide text-muted">{t("report.verdict")}</p>
              <h2 className={cn("mt-2 font-serif text-2xl leading-tight", verdictColor(report.verdict))}>
                {t(`verdict.${report.verdict}`)}
              </h2>
              <p className="mt-2 text-sm text-muted">
                {report.regionName[lang] ?? report.regionName.en} · {report.os}
              </p>
              <ul className="mt-4 grid grid-cols-2 gap-2">
                {STATUSES.map((status) => (
                  <li key={status} className="rounded-2xl bg-paper px-3 py-2">
                    <div className="text-lg font-semibold">{counts[status]}</div>
                    <div className="text-xs text-muted">{t(`counts.${status}`)}</div>
                  </li>
                ))}
              </ul>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={() => exportReport("json")}>
                  {t("export.json")}
                </Button>
                <Button size="sm" variant="outline" onClick={() => exportReport("md")}>
                  {t("export.md")}
                </Button>
              </div>
              {saved && <p className="mt-3 break-all text-xs text-muted">{saved}</p>}
              {report.browserUrl && (
                <p className="mt-3 break-all text-xs text-muted">
                  {report.browserOpened ? report.browserUrl : report.browserUrl}
                </p>
              )}
            </aside>
            <div className="space-y-5">
              {GROUPS.map((category) => {
                const items = report.checks.filter((check) => check.category === category);
                if (items.length === 0) return null;
                return (
                  <section key={category}>
                    <h3 className="mb-2 px-1 text-xs font-semibold uppercase tracking-[0.14em] text-muted">{t(`group.${category}`)}</h3>
                    <div className="space-y-2">
                      {items.map((check) => (
                        <CheckCard key={check.id} check={check} />
                      ))}
                    </div>
                  </section>
                );
              })}
              <p className="px-1 text-xs leading-5 text-muted">{t("phase.note")}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Notice({ tone, title, body }: { tone: "info" | "risk"; title: string; body: string }) {
  return (
    <article
      className={cn(
        "rounded-2xl border px-4 py-3",
        tone === "info" ? "border-notice-info-border bg-notice-info-bg" : "border-notice-risk-border bg-notice-risk-bg",
      )}
    >
      <h2 className={cn("text-sm font-semibold", tone === "info" ? "text-notice-info-ink" : "text-notice-risk-ink")}>{title}</h2>
      <p className="mt-1 text-sm leading-6 text-ink/80">{body}</p>
    </article>
  );
}

function CheckCard({ check }: { check: CheckResult }) {
  const { t } = useI18n();
  const border = {
    pass: "border-l-status-pass-border",
    warn: "border-l-status-warn-border",
    fail: "border-l-status-fail-border",
    info: "border-l-status-neutral-border",
    inconclusive: "border-l-status-neutral-border",
  }[check.status];
  return (
    <details open={check.status === "fail"} className={cn("rounded-2xl border border-line border-l-4 bg-card px-4 py-3", border)}>
      <summary className="flex cursor-pointer list-none items-start justify-between gap-3">
        <span>
          <span className="block text-sm font-semibold">{t(`check.${check.id}.title`)}</span>
          <span className="mt-1 block text-sm text-muted">{t(check.summaryKey, check.summaryParams)}</span>
        </span>
        <StatusBadge status={check.status} label={t(`status.${check.status}`)} />
      </summary>
      <div className="mt-3 grid gap-3 border-t border-line pt-3 text-sm md:grid-cols-2">
        <FieldList title={t("field.observed")} entries={check.observed} />
        <FieldList title={t("field.expected")} entries={check.expected} />
        <div className="rounded-2xl bg-paper px-3 py-2 md:col-span-2">
          <div className="text-xs font-semibold uppercase tracking-wide text-muted">{t("field.advice")}</div>
          <p className="mt-1 leading-6">{t(check.adviceKey, check.adviceParams)}</p>
        </div>
      </div>
    </details>
  );
}

function FieldList({ title, entries }: { title: string; entries: Record<string, string> }) {
  const rows = Object.entries(entries);
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-wide text-muted">{title}</div>
      {rows.length === 0 ? (
        <p className="mt-1 text-muted">—</p>
      ) : (
        <dl className="mt-1 space-y-1">
          {rows.map(([key, value]) => (
            <div key={key} className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-2">
              <dt className="text-muted">{key}</dt>
              <dd className="break-words">{value}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function verdictColor(verdict: Verdict) {
  if (verdict === "consistent") return "text-status-pass-ink";
  if (verdict === "review") return "text-status-warn-ink";
  if (verdict === "exposed") return "text-status-fail-ink";
  return "text-status-neutral-ink";
}
