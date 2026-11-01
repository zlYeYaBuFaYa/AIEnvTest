use async_trait::async_trait;

use crate::context::ScanContext;
use crate::i18n;
use crate::model::{CheckMeta, CheckResult, Judgement};

/// A read-only environment signal. Mutations live in the transaction service.
#[async_trait]
pub trait EnvironmentCheck: Send + Sync {
    fn meta(&self) -> CheckMeta;
    async fn detect(&self, ctx: &ScanContext) -> CheckResult;
}

pub fn finish(meta: &CheckMeta, mut judgement: Judgement) -> CheckResult {
    for map in [&mut judgement.observed, &mut judgement.expected, &mut judgement.summary_params, &mut judgement.advice_params] {
        for value in map.values_mut() { *value = crate::redact::redact_text(value); }
    }
    CheckResult {
        id: meta.id.to_string(),
        category: meta.category.to_string(),
        status: judgement.status,
        observed: judgement.observed,
        expected: judgement.expected,
        summary_en: i18n::tr("en", &judgement.summary_key, &judgement.summary_params),
        advice_en: i18n::tr("en", &judgement.advice_key, &judgement.advice_params),
        summary_key: judgement.summary_key,
        summary_params: judgement.summary_params,
        advice_key: judgement.advice_key,
        advice_params: judgement.advice_params,
    }
}
