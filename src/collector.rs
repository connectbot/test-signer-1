//! Durable, authenticated external ledger. Compiled only for the host collector.
use crate::ledger::{Activation, Claimed, Job};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
#[derive(Clone)]
pub struct Store {
    db: Arc<Mutex<Connection>>,
    token_hash: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub listen: String,
    pub tls_certificate: std::path::PathBuf,
    pub tls_private_key: std::path::PathBuf,
    pub token_file: std::path::PathBuf,
    pub database: std::path::PathBuf,
}
fn rejected(_: anyhow::Error) -> (StatusCode, &'static str) {
    (StatusCode::CONFLICT, "ledger operation rejected")
}
impl Store {
    pub fn open(path: &std::path::Path, token: &[u8]) -> Result<Self> {
        use sha2::{Digest, Sha256};
        ensure!(token.len() >= 32, "audit token too short");
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)?;
        }
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS policies(repo INTEGER PRIMARY KEY, revision INTEGER NOT NULL, hash TEXT NOT NULL, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, repo INTEGER NOT NULL, policy TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', lease TEXT, lease_until INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, retry_after INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS events(job TEXT NOT NULL REFERENCES jobs(id), seq INTEGER NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(job,seq));")?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            token_hash: Sha256::digest(token).into(),
        })
    }
    fn auth(&self, headers: &HeaderMap) -> Result<()> {
        use sha2::{Digest, Sha256};
        let value = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("");
        let actual: [u8; 32] = Sha256::digest(value.as_bytes()).into();
        ensure!(bool::from(actual.ct_eq(&self.token_hash)), "unauthorized");
        Ok(())
    }
    pub fn activate(&self, a: &Activation) -> Result<()> {
        ensure!(
            a.repository_id > 0 && a.revision > 0 && valid_hash(&a.policy_hash),
            "invalid activation"
        );
        ensure!(
            !a.classical_history.is_empty()
                && a.classical_history
                    .iter()
                    .chain(&a.hybrid_history)
                    .all(|h| valid_hash(h)),
            "invalid key history"
        );
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        let prior: Option<String> = tx
            .query_row(
                "SELECT body FROM policies WHERE repo=?1",
                [a.repository_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            let prior: Activation = serde_json::from_str(&prior)?;
            ensure!(a.revision >= prior.revision, "stale policy revision");
            if a.revision == prior.revision {
                ensure!(a.policy_hash == prior.policy_hash, "policy revision reused");
                return Ok(());
            }
            ensure!(
                a.classical_history.starts_with(&prior.classical_history)
                    && a.hybrid_history.starts_with(&prior.hybrid_history),
                "lineage regression or fork"
            );
        }
        tx.execute("INSERT INTO policies(repo,revision,hash,body) VALUES(?1,?2,?3,?4) ON CONFLICT(repo) DO UPDATE SET revision=excluded.revision,hash=excluded.hash,body=excluded.body",params![a.repository_id,a.revision,a.policy_hash,serde_json::to_string(a)?])?;
        tx.commit()?;
        Ok(())
    }
    pub fn enqueue(&self, job: &Job) -> Result<()> {
        ensure!(
            valid_hash(&job.policy_hash)
                && job.repository_id > 0
                && job.run_id > 0
                && job.attempt > 0
                && job.commit.len() == 40
                && job.commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid job"
        );
        ensure!(
            job.id
                == crate::ledger::job_id(
                    job.repository_id,
                    job.run_id,
                    job.attempt,
                    &job.policy_hash
                ),
            "job identifier differs"
        );
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        let active: (u64, String) = tx.query_row(
            "SELECT revision,hash FROM policies WHERE repo=?1",
            [job.repository_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            active == (job.revision, job.policy_hash.clone()),
            "job uses inactive policy"
        );
        let existing: Option<String> = tx
            .query_row("SELECT body FROM jobs WHERE id=?1", [&job.id], |r| r.get(0))
            .optional()?;
        if let Some(existing) = existing {
            ensure!(
                serde_json::from_str::<Job>(&existing)? == *job,
                "conflicting job"
            );
            return Ok(());
        }
        tx.execute(
            "INSERT INTO jobs(id,repo,policy,body) VALUES(?1,?2,?3,?4)",
            params![
                job.id,
                job.repository_id,
                job.policy_hash,
                serde_json::to_string(job)?
            ],
        )?;
        append(&tx, &job.id, "job.accepted", json!({"job":job}))?;
        tx.commit()?;
        Ok(())
    }
    pub fn claim(&self) -> Result<Option<Claimed>> {
        use rand::RngCore;
        let now = crate::config::now()?;
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        let exhausted = {
            let mut q = tx.prepare(
                "SELECT id FROM jobs WHERE status='running' AND lease_until < ?1 AND attempts >= 6",
            )?;
            q.query_map([now], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for id in exhausted {
            append(
                &tx,
                &id,
                "job.interrupted",
                json!({"signing_outcome":"uncertain; retry limit exhausted"}),
            )?;
            append(
                &tx,
                &id,
                "job.finished",
                json!({"status":"rejected","reason":"retry-limit"}),
            )?;
            tx.execute(
                "UPDATE jobs SET status='rejected',lease=NULL,lease_until=0 WHERE id=?1",
                [id],
            )?;
        }
        let row:Option<(String,String,u64,String)>=tx.query_row("SELECT j.id,j.body,j.attempts,j.status FROM jobs j JOIN policies p ON p.repo=j.repo AND p.hash=j.policy WHERE j.status IN ('pending','running') AND j.lease_until < ?1 AND j.retry_after <= ?1 AND j.attempts < 6 ORDER BY j.rowid LIMIT 1",[now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let Some((id, body, attempt, status)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let mut bytes = [0; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut bytes)?;
        let lease = hex::encode(bytes);
        tx.execute("UPDATE jobs SET status='running',lease=?1,lease_until=?2,attempts=attempts+1 WHERE id=?3",params![lease,now+300,id])?;
        if status == "running" {
            append(
                &tx,
                &id,
                "job.interrupted",
                json!({"previous_attempt":attempt,"signing_outcome":"uncertain; inspect prior intent/result events"}),
            )?;
        }
        append(&tx, &id, "job.claimed", json!({"attempt":attempt+1}))?;
        tx.commit()?;
        Ok(Some(Claimed {
            job: serde_json::from_str(&body)?,
            lease,
            attempt: attempt + 1,
        }))
    }
    pub fn event(&self, id: &str, lease: &str, kind: &str, data: Value) -> Result<()> {
        ensure!(kind.len() <= 100 && !kind.is_empty(), "invalid event kind");
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        check_lease(&tx, id, lease)?;
        append(&tx, id, kind, data)?;
        tx.execute(
            "UPDATE jobs SET lease_until=?1 WHERE id=?2",
            params![crate::config::now()? + 300, id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn finish(&self, id: &str, lease: &str, status: &str) -> Result<()> {
        ensure!(
            ["complete", "rejected", "retry"].contains(&status),
            "invalid job outcome"
        );
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let tx = db.transaction()?;
        check_lease(&tx, id, lease)?;
        let attempts: u64 =
            tx.query_row("SELECT attempts FROM jobs WHERE id=?1", [id], |r| r.get(0))?;
        let state = if status == "retry" && attempts < 6 {
            "pending"
        } else if status == "retry" {
            "rejected"
        } else {
            status
        };
        append(
            &tx,
            id,
            "job.finished",
            json!({"status":state,"requested":status}),
        )?;
        tx.execute(
            "UPDATE jobs SET status=?1,lease=NULL,lease_until=0,retry_after=?2 WHERE id=?3",
            params![state, crate::config::now()? + 30 * attempts, id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn inspect(&self, id: &str) -> Result<Value> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("ledger lock failed"))?;
        let (body, status): (String, String) =
            db.query_row("SELECT body,status FROM jobs WHERE id=?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        let mut q =
            db.prepare("SELECT seq,kind,body,previous,hash FROM events WHERE job=?1 ORDER BY seq")?;
        let events=q.query_map([id],|r|Ok(json!({"sequence":r.get::<_,u64>(0)?,"kind":r.get::<_,String>(1)?,"body":serde_json::from_str::<Value>(&r.get::<_,String>(2)?).unwrap_or(Value::Null),"previous":r.get::<_,String>(3)?,"hash":r.get::<_,String>(4)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(json!({"job":serde_json::from_str::<Value>(&body)?,"status":status,"events":events}))
    }
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn check_lease(tx: &rusqlite::Transaction<'_>, id: &str, lease: &str) -> Result<()> {
    let (actual,until,status,policy,active):(Option<String>,u64,String,String,String)=tx.query_row("SELECT j.lease,j.lease_until,j.status,j.policy,p.hash FROM jobs j JOIN policies p ON p.repo=j.repo WHERE j.id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    ensure!(
        actual.as_deref() == Some(lease)
            && until >= crate::config::now()?
            && status == "running"
            && policy == active,
        "expired lease or inactive policy"
    );
    Ok(())
}
fn append(tx: &rusqlite::Transaction<'_>, job: &str, kind: &str, data: Value) -> Result<()> {
    let prior: Option<(u64, String)> = tx
        .query_row(
            "SELECT seq,hash FROM events WHERE job=?1 ORDER BY seq DESC LIMIT 1",
            [job],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (seq, previous) = prior.map(|(s, h)| (s + 1, h)).unwrap_or((1, String::new()));
    let body = serde_json::to_string(&json!({"time":crate::config::now()?,"data":data}))?;
    let hash = crate::sha256(&serde_json::to_vec(&json!([
        job, seq, kind, &body, &previous
    ]))?);
    tx.execute(
        "INSERT INTO events(job,seq,kind,body,previous,hash) VALUES(?1,?2,?3,?4,?5,?6)",
        params![job, seq, kind, body, previous, hash],
    )?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    lease: String,
    kind: String,
    data: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    lease: String,
    status: String,
}
fn authorize(
    store: &Store,
    headers: &HeaderMap,
) -> std::result::Result<(), (StatusCode, &'static str)> {
    store
        .auth(headers)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized"))
}
pub fn router(store: Store) -> Router {
    Router::new()
        .route(
            "/v1/health",
            get(|State(s): State<Store>, h: HeaderMap| async move {
                authorize(&s, &h)?;
                Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
            }),
        )
        .route(
            "/v1/policies",
            post(
                |State(s): State<Store>, h: HeaderMap, Json(a): Json<Activation>| async move {
                    authorize(&s, &h)?;
                    s.activate(&a).map_err(rejected)?;
                    Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
                },
            ),
        )
        .route(
            "/v1/jobs",
            post(
                |State(s): State<Store>, h: HeaderMap, Json(j): Json<Job>| async move {
                    authorize(&s, &h)?;
                    s.enqueue(&j).map_err(rejected)?;
                    Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
                },
            ),
        )
        .route(
            "/v1/claim",
            post(|State(s): State<Store>, h: HeaderMap| async move {
                authorize(&s, &h)?;
                let j = s.claim().map_err(rejected)?;
                Ok::<_, (StatusCode, &'static str)>(Json(
                    serde_json::to_value(j)
                        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "encoding error"))?,
                ))
            }),
        )
        .route(
            "/v1/jobs/{id}/events",
            post(
                |State(s): State<Store>,
                 h: HeaderMap,
                 Path(id): Path<String>,
                 Json(e): Json<Event>| async move {
                    authorize(&s, &h)?;
                    s.event(&id, &e.lease, &e.kind, e.data).map_err(rejected)?;
                    Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
                },
            ),
        )
        .route(
            "/v1/jobs/{id}/finish",
            post(
                |State(s): State<Store>,
                 h: HeaderMap,
                 Path(id): Path<String>,
                 Json(f): Json<Finish>| async move {
                    authorize(&s, &h)?;
                    s.finish(&id, &f.lease, &f.status).map_err(rejected)?;
                    Ok::<_, (StatusCode, &'static str)>(Json(json!({"ok":true})))
                },
            ),
        )
        .route(
            "/v1/jobs/{id}",
            get(
                |State(s): State<Store>, h: HeaderMap, Path(id): Path<String>| async move {
                    authorize(&s, &h)?;
                    s.inspect(&id).map(Json).map_err(rejected)
                },
            ),
        )
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(store)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_leases_recover_and_stop_at_retry_limit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(
            &dir.path().join("ledger.sqlite"),
            b"01234567890123456789012345678901",
        )
        .unwrap();
        let hash = "a".repeat(64);
        store
            .activate(&Activation {
                repository_id: 1,
                revision: 1,
                policy_hash: hash.clone(),
                classical_history: vec!["b".repeat(64)],
                hybrid_history: vec![],
            })
            .unwrap();
        let job = Job {
            id: crate::ledger::job_id(1, 2, 1, &hash),
            repository_id: 1,
            run_id: 2,
            attempt: 1,
            commit: "c".repeat(40),
            policy_hash: hash,
            revision: 1,
        };
        store.enqueue(&job).unwrap();
        let first = store.claim().unwrap().unwrap();
        store
            .db
            .lock()
            .unwrap()
            .execute("UPDATE jobs SET lease_until=0", [])
            .unwrap();
        let second = store.claim().unwrap().unwrap();
        assert_ne!(first.lease, second.lease);
        assert!(
            store
                .event(&job.id, &first.lease, "sign.intent", json!({}))
                .is_err()
        );
        assert!(
            store.inspect(&job.id).unwrap()["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["kind"] == "job.interrupted")
        );
        store
            .db
            .lock()
            .unwrap()
            .execute("UPDATE jobs SET lease_until=0, attempts=6", [])
            .unwrap();
        assert!(store.claim().unwrap().is_none());
        assert_eq!(store.inspect(&job.id).unwrap()["status"], "rejected");
        let mut h = HeaderMap::new();
        assert!(store.auth(&h).is_err());
        h.insert(
            "authorization",
            "Bearer 01234567890123456789012345678901".parse().unwrap(),
        );
        store.auth(&h).unwrap();
    }
    #[test]
    fn durable_dedup_claim_and_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.sqlite");
        let token = b"01234567890123456789012345678901";
        let s = Store::open(&path, token).unwrap();
        let hash = "a".repeat(64);
        let a = Activation {
            repository_id: 1,
            revision: 1,
            policy_hash: hash.clone(),
            classical_history: vec!["b".repeat(64)],
            hybrid_history: vec![],
        };
        s.activate(&a).unwrap();
        let job = Job {
            id: crate::ledger::job_id(1, 2, 1, &hash),
            repository_id: 1,
            run_id: 2,
            attempt: 1,
            commit: "c".repeat(40),
            policy_hash: hash,
            revision: 1,
        };
        s.enqueue(&job).unwrap();
        s.enqueue(&job).unwrap();
        let claimed = s.claim().unwrap().unwrap();
        assert!(s.claim().unwrap().is_none());
        assert!(s.event(&job.id, "invalid", "test", json!({})).is_err());
        s.event(&job.id, &claimed.lease, "sign.intent", json!({"key":"A"}))
            .unwrap();
        s.finish(&job.id, &claimed.lease, "complete").unwrap();
        drop(s);
        let s = Store::open(&path, token).unwrap();
        assert!(s.claim().unwrap().is_none());
        assert_eq!(s.inspect(&job.id).unwrap()["status"], "complete");
        let mut newer = a.clone();
        newer.revision = 2;
        newer.policy_hash = "d".repeat(64);
        newer.classical_history.push("e".repeat(64));
        s.activate(&newer).unwrap();
        assert!(s.activate(&a).is_err());
        newer.revision = 3;
        newer.classical_history.remove(0);
        assert!(s.activate(&newer).is_err());
    }
}
