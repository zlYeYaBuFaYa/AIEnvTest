use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::context::ScanContext;
use crate::i18n;
use crate::model::{CheckMeta, CheckResult, Judgement};

/// One environment signal.
///
/// Phase 1 implements [`EnvironmentCheck::detect`] only.
/// [`backup`](EnvironmentCheck::backup), [`restore`](EnvironmentCheck::restore),
/// and [`fix`](EnvironmentCheck::fix) stay on the trait so Phase 2 can fill
/// them in without a second redesign. Their default bodies return
/// [`PhaseError::NotImplemented`] and must not change the machine.
#[async_trait]
pub trait EnvironmentCheck: Send + Sync {
    fn meta(&self) -> CheckMeta;

    async fn detect(&self, ctx: &ScanContext) -> CheckResult;

    async fn backup(&self, _ctx: &ScanContext) -> Result<BackupBlob, PhaseError> {
        Err(PhaseError::NotImplemented)
    }

    async fn restore(&self, _ctx: &ScanContext, _backup: &BackupBlob) -> Result<(), PhaseError> {
        Err(PhaseError::NotImplemented)
    }

    async fn fix(&self, _ctx: &ScanContext) -> Result<FixReport, PhaseError> {
        Err(PhaseError::NotImplemented)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupBlob {
    pub id: String,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixReport {
    pub id: String,
    pub changed: bool,
    pub detail: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PhaseError {
    #[error("backup, restore, and repair are not implemented until Phase 2")]
    NotImplemented,
    #[error("{0}")]
    Failed(String),
}

pub fn finish(meta: &CheckMeta, judgement: Judgement) -> CheckResult {
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
