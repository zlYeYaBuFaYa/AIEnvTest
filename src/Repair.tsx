import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui";
import { useI18n } from "@/lib/i18n";
import type { ScanReport } from "@/lib/types";
type TunnelException = { endpoint: string; port: number; resolver: string };
type Resource = { kind: string; value?: string };
type Plan = { id: string; check_id: string; requires_admin: boolean; guidance: {type: "location_settings"} | null; preview: {resource: Resource; before: string; after: string}[] };
type Backup = { id: string; created_at: string; check_id: string; scope: Resource[]; integrity: boolean };
type Update = { transactions: {success: boolean; steps: {index: number; status: string; error: string | null}[]}[]; report: ScanReport | null; scan_error: string | null };
export function useRepair(report: ScanReport | null, setReport: (r: ScanReport) => void, setError: (s: string) => void, scanning: boolean) {
  const { t } = useI18n();
  const [backups, setBackups] = useState<Backup[]>([]);
  const [available, setAvailable] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const gate = useRef(false);
  const [history, setHistory] = useState(false);
  const [modal, setModal] = useState<{plans?: Plan[]; backupId?: string; all?: boolean} | null>(null);
  const [udpTarget, setUdpTarget] = useState<string | undefined>("udp_quic");
  const [udpForm, setUdpForm] = useState(false);
  const [udpEndpoint, setUdpEndpoint] = useState("");
  const [udpPort, setUdpPort] = useState("51820");
  const [udpResolver, setUdpResolver] = useState("");
  const [notice, setNotice] = useState("");
  const blocked = busy || scanning;
  async function reload() {
    setAvailable([]);
    setBackups(await invoke<Backup[]>("list_backups"));
    setAvailable(["hosts", ...(report ? ["timezone", "clock", "locale", "dns_configured", "exit_ipv6", "system_proxy", "udp_quic", ...(report.os === "windows" ? ["location"] : [])] : [])]);
  }
  useEffect(() => { void reload().catch(e => setError(String(e))); }, [report]);
  async function perform(work: () => Promise<void>) {
    if (gate.current) return;
    gate.current = true; setBusy(true); setError(""); setNotice("");
    try { await work(); } catch(e) { const error = String(e); setError(error.startsWith("repair.") ? t(error) : error); }
    finally { try { await reload(); } catch(e) { const error = String(e); setError(error.startsWith("repair.") ? t(error) : error); } gate.current = false; setBusy(false); }
  }
  async function preview(checkId?: string, udp?: TunnelException) {
    if (!udp && (checkId === "udp_quic" || (!checkId && report?.checks.some(c => c.id === "udp_quic" && c.status === "fail")))) { setUdpTarget(checkId); setUdpForm(true); return; }
    await perform(async () => {
      const plans = checkId ? [await invoke<Plan | null>("plan_fix", {checkId, udp: udp ?? null})].filter((p): p is Plan => !!p) : await invoke<Plan[]>("plan_fix_all_failed", {udp: udp ?? null});
      if (plans.length) setModal({plans}); else setNotice(t("repair.none"));
    });
  }
  async function confirm() {
    if (!modal) return;
    const action = modal; setModal(null);
    await perform(async () => {
      const updates: Update[] = [];
      if (action.plans) for (const plan of action.plans) {
        if (plan.guidance) {await invoke("open_location_settings"); setNotice(t("repair.guidance"));}
        else updates.push(await invoke<Update>("apply_plan", {planId: plan.id}));
      }
      else updates.push(await invoke<Update>(action.all ? "restore_all" : "restore", {backupId: action.backupId}));
      for (const update of updates) {
        if (update.report) setReport(update.report);
        if (update.scan_error) setError(update.scan_error);
        if (update.transactions.some(r => !r.success)) setError(t("repair.failed") + " " + update.transactions.flatMap(r => r.steps.filter(s => s.error).map(s => `${s.index + 1}: ${s.status}: ${s.error?.startsWith("repair.") ? t(s.error) : s.error}`)).join("; "));
        else if (!update.scan_error) setNotice(t("repair.success"));
      }
    });
  }
  const actions = (checkId: string) => {
    const latest = backups.find(b => b.check_id === checkId && b.integrity);
    return <div className="mt-3 flex flex-wrap gap-2">
      <Button size="sm" variant="outline" disabled={blocked || (checkId !== "location" && !available.includes(checkId))} onClick={() => void preview(checkId)}>{t(checkId === "location" && report?.os !== "windows" ? "repair.openSettings" : "repair.fix")}</Button>
      <Button size="sm" variant="outline" disabled={blocked || !["hosts", "timezone", "clock", "locale", "dns_configured", "exit_ipv6", "system_proxy", "udp_quic", ...(report?.os === "windows" ? ["location"] : [])].includes(checkId)} onClick={() => void perform(async () => { await invoke("backup", {checkId}); setNotice(t("repair.saved")); })}>{t("repair.backup")}</Button>
      <Button size="sm" variant="outline" disabled={blocked || !latest} onClick={() => setModal({backupId: latest?.id})}>{t("repair.restore")}</Button>
    </div>;
  };
  const sidebar = <div className="mt-4 space-y-2 border-t border-line pt-4">
    <Button size="sm" disabled={blocked} onClick={() => void preview()}>{t("repair.all")}</Button>
    {busy && <p role="status" className="text-sm text-teal">{t("repair.working")}</p>}
    {notice && <p role="status" className="text-sm text-muted">{notice}</p>}
  </div>;
  const overlays = <>
    {udpForm && <Confirmation title={t("repair.udpTitle")} close={() => setUdpForm(false)} confirm={() => {setUdpForm(false); void preview(udpTarget, {endpoint: udpEndpoint.trim(), port: Number(udpPort), resolver: udpResolver.trim()});}}>
      <p className="mb-4 text-sm text-muted">{t("repair.udpExplanation")}</p>
      {[["repair.udpEndpoint", udpEndpoint, setUdpEndpoint], ["repair.udpPort", udpPort, setUdpPort], ["repair.udpResolver", udpResolver, setUdpResolver]].map(([label, value, setter]) => <label key={String(label)} className="mb-3 block text-sm">{t(String(label))}<input className="mt-1 block w-full rounded-lg border border-line bg-paper p-2 text-ink" value={String(value)} onChange={e => (setter as (v: string) => void)(e.target.value)} /></label>)}
    </Confirmation>}
    {history && <HistoryDrawer title={t("repair.history")} close={() => setHistory(false)}>
        <div className="flex items-center justify-between gap-3"><h2 className="font-serif text-2xl">{t("repair.history")}</h2><Button variant="outline" size="sm" onClick={() => setHistory(false)}>{t("repair.close")}</Button></div>
        <p className="my-4 text-sm text-muted">{t("repair.home")}</p>
        <Button disabled={blocked || !backups.length} onClick={() => setModal({all: true})}>{t("repair.restoreAll")}</Button>
        {!backups.length && <p className="mt-6 text-muted">{t("repair.empty")}</p>}
        {backups.map(b => <article key={b.id} className="mt-4 rounded-2xl border border-line bg-paper p-4">
          <p className="font-semibold">{b.check_id ? t(`check.${b.check_id}.title`) : t("repair.invalid")}</p>
          <p className="mt-1 text-sm text-muted">{b.created_at ? new Date(b.created_at).toLocaleString() : "—"}</p>
          <p className="my-2 break-all text-sm">{b.scope.map(r => r.value ?? r.kind).join(", ")}</p>
          <p className={b.integrity ? "text-teal" : "text-status-fail-ink"}>{t(b.integrity ? "repair.verified" : "repair.invalid")}</p>
          <Button size="sm" variant="outline" disabled={blocked || !b.integrity} onClick={() => setModal({backupId: b.id})}>{t("repair.restore")}</Button>
        </article>)}
    </HistoryDrawer>}
    {modal && <Confirmation title={t(modal.plans ? "repair.preview" : modal.all ? "repair.restoreAll" : "repair.restore")} close={() => setModal(null)} confirm={() => void confirm()} guidance={modal.plans?.every(p => !!p.guidance)}>
      <p className="mb-4 text-sm text-muted">{t(modal.plans?.every(p => !!p.guidance) ? "repair.guidance" : modal.plans ? "repair.confirmFix" : modal.all ? "repair.home" : "repair.confirmRestore")}</p>
      {modal.plans?.map(plan => <div key={plan.id} className="space-y-3">
        {plan.check_id === "locale" && <p className="text-sm text-muted">{t("repair.logoutNote")}</p>}
        {plan.check_id === "clock" && <p className="text-sm text-muted">{t("repair.ntpNote")}</p>}
        {plan.requires_admin && <span className="inline-block rounded-full bg-notice-risk-bg px-3 py-1 text-xs text-notice-risk-ink">{t("repair.admin")}</span>}
        {plan.preview.map((change, i) => <div key={i} className="rounded-2xl border border-line bg-paper p-3">
          <p className="mb-2 break-all font-mono text-sm">{change.resource.value ?? change.resource.kind}</p>
          <div className="grid gap-3 sm:grid-cols-2"><div><p className="text-xs text-muted">{t("repair.before")}</p><pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{change.before}</pre></div><div><p className="text-xs text-teal">→ {t("repair.after")}</p><pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{change.after}</pre></div></div>
        </div>)}
      </div>)}
    </Confirmation>}
  </>;
  return {actions, sidebar, overlays, busy: busy || !!modal || udpForm, historyButton: <Button size="sm" variant="outline" disabled={blocked} onClick={() => setHistory(true)}>{t("repair.history")}</Button>};
}
function Confirmation({title, children, close, confirm, guidance}: {guidance?: boolean; title: string; children: React.ReactNode; close: () => void; confirm: () => void}) {
  const { t } = useI18n();
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { const el = dialog.current; el?.showModal(); return () => { el?.close(); }; }, []);
  return <dialog ref={dialog} aria-label={title} onCancel={close} className="max-h-[85vh] w-[90vw] max-w-3xl overflow-auto rounded-3xl border border-line bg-card p-6 text-ink shadow-card backdrop:bg-ink/30">
    <h2 className="mb-4 font-serif text-2xl">{title}</h2>{children}
    <div className="mt-6 flex justify-end gap-2"><Button variant="outline" onClick={close}>{t("repair.cancel")}</Button><Button onClick={confirm}>{t(guidance ? "repair.openSettings" : "repair.confirm")}</Button></div>
  </dialog>;
}

function HistoryDrawer({ title, close, children }: { title: string; close: () => void; children: React.ReactNode }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { const el = dialog.current; el?.showModal(); return () => { el?.close(); }; }, []);
  return <dialog ref={dialog} aria-label={title} onCancel={close} className="fixed inset-y-0 left-auto right-0 m-0 h-full max-h-full w-full max-w-xl overflow-y-auto border-l border-line bg-card p-6 text-ink shadow-card backdrop:bg-ink/30">{children}</dialog>;
}
