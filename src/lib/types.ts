export type Status = "pass" | "warn" | "fail" | "info" | "inconclusive";
export type Verdict = "consistent" | "review" | "exposed" | "inconclusive";

export interface CheckResult {
  id: string;
  category: string;
  status: Status;
  observed: Record<string, string>;
  expected: Record<string, string>;
  summaryKey: string;
  summaryParams: Record<string, string>;
  adviceKey: string;
  adviceParams: Record<string, string>;
  summaryEn: string;
  adviceEn: string;
}

export interface ScanReport {
  generatedAt: string;
  os: string;
  regionId: string;
  regionName: Record<string, string>;
  verdict: Verdict;
  checks: CheckResult[];
  browserUrl: string;
  browserOpened: boolean;
  phase: number;
}

export interface RegionSummary {
  id: string;
  country: string;
  group: string;
  name: Record<string, string>;
  timezones: string[];
  languages: string[];
}

export type Lang = "en" | "zh-CN" | "ja" | "ko";
