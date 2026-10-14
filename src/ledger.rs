use crate::{
    config::{Config, read_secret},
    github::bounded,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub id: String,
    pub repository_id: u64,
    pub run_id: u64,
    pub attempt: u64,
    pub commit: String,
    pub policy_hash: String,
    pub revision: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub repository_id: u64,
    pub revision: u64,
    pub policy_hash: String,
    pub classical_history: Vec<String>,
    pub hybrid_history: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claimed {
    pub job: Job,
    pub lease: String,
    pub attempt: u64,
}
#[derive(Clone)]
pub struct Ledger {
    client: reqwest::Client,
    base: String,
    token: String,
}
impl Ledger {
    pub fn new(config: &Config) -> Result<Self> {
        let ca = reqwest::Certificate::from_pem(&std::fs::read(&config.audit_ca_certificate)?)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(ca)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let token = read_secret(&config.audit_token)?;
        let token = std::str::from_utf8(&token)?.trim().to_string();
        ensure!(token.len() >= 32, "audit token too short");
        Ok(Self {
            client,
            base: config.audit_url.clone(),
            token,
        })
    }
    async fn post(&self, path: &str, body: &impl Serialize) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await?;
        Ok(serde_json::from_slice(
            &bounded(response, 8 * 1024 * 1024).await?,
        )?)
    }
    pub async fn activate(&self, activation: &Activation) -> Result<()> {
        self.post("/v1/policies", activation).await?;
        Ok(())
    }
    pub async fn enqueue(&self, job: &Job) -> Result<()> {
        self.post("/v1/jobs", job).await?;
        Ok(())
    }
    pub async fn claim(&self) -> Result<Option<Claimed>> {
        let value = self.post("/v1/claim", &serde_json::json!({})).await?;
        if value.is_null() {
            Ok(None)
        } else {
            Ok(Some(serde_json::from_value(value)?))
        }
    }
    pub async fn event(&self, claimed: &Claimed, kind: &str, data: Value) -> Result<()> {
        self.post(
            &format!("/v1/jobs/{}/events", claimed.job.id),
            &serde_json::json!({"lease":claimed.lease,"kind":kind,"data":data}),
        )
        .await?;
        Ok(())
    }
    pub async fn finish(&self, claimed: &Claimed, status: &str) -> Result<()> {
        self.post(
            &format!("/v1/jobs/{}/finish", claimed.job.id),
            &serde_json::json!({"lease":claimed.lease,"status":status}),
        )
        .await?;
        Ok(())
    }
    pub async fn ping(&self) -> Result<()> {
        let response = self
            .client
            .get(format!("{}/v1/health", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?;
        bounded(response, 1024).await?;
        Ok(())
    }
}
pub fn job_id(repository: u64, run: u64, attempt: u64, policy: &str) -> String {
    format!("{repository}-{run}-{attempt}-{policy}")
}
