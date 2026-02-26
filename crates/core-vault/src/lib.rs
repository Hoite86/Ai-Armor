use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use core_crypto::{generate_passphrase, protect_with_dpapi, unprotect_with_dpapi};
use core_model::{EntityKind, SessionRecord, TokenMapping};
use core_tokenize::extract_tokens;
use rusqlite::{params, Connection};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum TtlOption {
    OneHour,
    OneDay,
    SevenDays,
}
impl TtlOption {
    pub fn duration(self) -> Duration {
        match self {
            Self::OneHour => Duration::hours(1),
            Self::OneDay => Duration::hours(24),
            Self::SevenDays => Duration::days(7),
        }
    }
}

pub struct Vault {
    conn: Connection,
    key_file: PathBuf,
}

impl Vault {
    pub fn open(db_path: impl AsRef<Path>, key_file: impl AsRef<Path>) -> Result<Self> {
        let key_file = key_file.as_ref().to_path_buf();
        let pass = ensure_passphrase(&key_file)?;
        let conn = Connection::open(db_path)?;
        conn.pragma_update(None, "key", pass)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                session_tag TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                text_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS mappings (
                session_id TEXT NOT NULL,
                token TEXT NOT NULL,
                value TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                PRIMARY KEY (session_id, token)
            );",
        )?;
        Ok(Self { conn, key_file })
    }

    pub fn store_session(
        &self,
        session_tag: &str,
        mappings: &[TokenMapping],
        ttl: TtlOption,
        text_hash: Option<&str>,
    ) -> Result<SessionRecord> {
        let now = Utc::now();
        let expires = now + ttl.duration();
        let id = Uuid::new_v4();
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for m in mappings {
            *by_type.entry(format!("{:?}", m.entity_type)).or_insert(0) += 1;
        }
        self.conn.execute(
            "INSERT INTO sessions(session_id, session_tag, created_at, expires_at, metadata_json, text_hash) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![id.to_string(), session_tag, now.to_rfc3339(), expires.to_rfc3339(), serde_json::to_string(&by_type)?, text_hash],
        )?;
        for m in mappings {
            self.conn.execute(
                "INSERT INTO mappings(session_id, token, value, entity_type) VALUES(?1, ?2, ?3, ?4)",
                params![id.to_string(), m.token, m.value, format!("{:?}", m.entity_type)],
            )?;
        }
        Ok(SessionRecord {
            session_id: id,
            session_tag: session_tag.to_string(),
            created_at: now,
            expires_at: expires,
            item_count: mappings.len(),
        })
    }

    pub fn load_mappings_for_restore(&self, text: &str) -> Result<Vec<TokenMapping>> {
        let toks = extract_tokens(text);
        if toks.is_empty() {
            return Ok(vec![]);
        }

        if let Some(tag) = toks.first().and_then(extract_tag) {
            if let Some(rows) = self.get_session_by_tag(tag)? {
                return Ok(rows);
            }
        }
        self.best_overlap_session(&toks)
    }

    pub fn purge_expired(&self) -> Result<usize> {
        let now = Utc::now().to_rfc3339();
        let mut stmt = self
            .conn
            .prepare("SELECT session_id FROM sessions WHERE expires_at <= ?1")?;
        let ids: Vec<String> = stmt
            .query_map(params![now], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut count = 0;
        for id in ids {
            count += self
                .conn
                .execute("DELETE FROM mappings WHERE session_id = ?1", params![&id])?;
            self.conn
                .execute("DELETE FROM sessions WHERE session_id = ?1", params![&id])?;
        }
        Ok(count)
    }

    pub fn purge_all(&self) -> Result<()> {
        self.conn.execute("DELETE FROM mappings", [])?;
        self.conn.execute("DELETE FROM sessions", [])?;
        Ok(())
    }

    pub fn key_file_path(&self) -> &Path {
        &self.key_file
    }

    fn get_session_by_tag(&self, tag: &str) -> Result<Option<Vec<TokenMapping>>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.token, m.value, m.entity_type
             FROM mappings m JOIN sessions s ON s.session_id = m.session_id
             WHERE s.session_tag = ?1 AND s.expires_at > ?2",
        )?;
        let now = Utc::now().to_rfc3339();
        let rows: Vec<TokenMapping> = stmt
            .query_map(params![tag, now], |r| {
                let kind: String = r.get(2)?;
                Ok(TokenMapping {
                    token: r.get(0)?,
                    value: r.get(1)?,
                    entity_type: parse_kind(&kind),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rows))
        }
    }

    fn best_overlap_session(&self, toks: &[String]) -> Result<Vec<TokenMapping>> {
        let candidates = self.recent_sessions(20)?;
        let input: HashSet<String> = toks.iter().cloned().collect();
        let mut best: Option<(usize, String)> = None;
        for sid in candidates {
            let tokset = self.tokens_for_session(&sid)?;
            let score = tokset.intersection(&input).count();
            if score > 0 && best.as_ref().map(|b| score > b.0).unwrap_or(true) {
                best = Some((score, sid));
            }
        }
        if let Some((_, sid)) = best {
            return self.mappings_for_session(&sid);
        }
        Ok(vec![])
    }

    fn recent_sessions(&self, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT session_id FROM sessions WHERE expires_at > ?1 ORDER BY created_at DESC LIMIT ?2")?;
        let now = Utc::now().to_rfc3339();
        Ok(stmt
            .query_map(params![now, limit as i64], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn tokens_for_session(&self, session_id: &str) -> Result<HashSet<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT token FROM mappings WHERE session_id=?1")?;
        Ok(stmt
            .query_map(params![session_id], |r| r.get(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?)
    }

    fn mappings_for_session(&self, session_id: &str) -> Result<Vec<TokenMapping>> {
        let mut stmt = self
            .conn
            .prepare("SELECT token, value, entity_type FROM mappings WHERE session_id=?1")?;
        Ok(stmt
            .query_map(params![session_id], |r| {
                let kind: String = r.get(2)?;
                Ok(TokenMapping {
                    token: r.get(0)?,
                    value: r.get(1)?,
                    entity_type: parse_kind(&kind),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn parse_kind(v: &str) -> EntityKind {
    match v {
        "Email" => EntityKind::Email,
        "Phone" => EntityKind::Phone,
        "Ssn" => EntityKind::Ssn,
        "Card" => EntityKind::Card,
        "Ip" => EntityKind::Ip,
        "Url" => EntityKind::Url,
        "Jwt" => EntityKind::Jwt,
        "ApiKey" => EntityKind::ApiKey,
        "Token" => EntityKind::Token,
        "PrivateKey" => EntityKind::PrivateKey,
        "Term" => EntityKind::Term,
        "Bearer" => EntityKind::Bearer,
        _ => EntityKind::Token,
    }
}

fn ensure_passphrase(path: &Path) -> Result<String> {
    if path.exists() {
        let c = fs::read(path)?;
        let plain = unprotect_with_dpapi(&c)?;
        return String::from_utf8(plain).map_err(|e| anyhow!(e));
    }
    let pass = generate_passphrase();
    let enc = protect_with_dpapi(pass.as_bytes())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, enc)?;
    Ok(pass)
}

fn extract_tag(token: &String) -> Option<&str> {
    token.strip_prefix("[[")?.split(':').next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn ttl_purge_works() {
        let d = tempdir().unwrap();
        let vault = Vault::open(d.path().join("v.db"), d.path().join("k.bin")).unwrap();
        let m = vec![TokenMapping {
            token: "[[AA1:EMAIL_01]]".into(),
            value: "a@b.com".into(),
            entity_type: EntityKind::Email,
        }];
        vault
            .store_session("AA1", &m, TtlOption::OneHour, None)
            .unwrap();
        vault
            .conn
            .execute(
                "UPDATE sessions SET expires_at = ?1",
                params![(Utc::now() - Duration::hours(2)).to_rfc3339()],
            )
            .unwrap();
        let purged = vault.purge_expired().unwrap();
        assert!(purged > 0);
    }

    #[test]
    fn session_matching_by_tag() {
        let d = tempdir().unwrap();
        let vault = Vault::open(d.path().join("v.db"), d.path().join("k.bin")).unwrap();
        let m = vec![TokenMapping {
            token: "[[AA1:EMAIL_01]]".into(),
            value: "a@b.com".into(),
            entity_type: EntityKind::Email,
        }];
        vault
            .store_session("AA1", &m, TtlOption::OneDay, None)
            .unwrap();
        let got = vault
            .load_mappings_for_restore("hello [[AA1:EMAIL_01]]")
            .unwrap();
        assert_eq!(got.len(), 1);
    }
}
