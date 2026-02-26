use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum EntityKind {
    Email,
    Phone,
    Ssn,
    Card,
    Ip,
    Url,
    Jwt,
    ApiKey,
    Token,
    PrivateKey,
    Term,
    Bearer,
}

impl EntityKind {
    pub fn priority(self) -> u8 {
        match self {
            EntityKind::PrivateKey | EntityKind::ApiKey | EntityKind::Token => 100,
            EntityKind::Card => 90,
            EntityKind::Ssn => 80,
            EntityKind::Jwt | EntityKind::Bearer => 70,
            EntityKind::Email => 60,
            EntityKind::Phone => 50,
            EntityKind::Ip | EntityKind::Url => 40,
            EntityKind::Term => 30,
        }
    }

    pub fn token_label(self) -> &'static str {
        match self {
            EntityKind::Email => "EMAIL",
            EntityKind::Phone => "PHONE",
            EntityKind::Ssn => "SSN",
            EntityKind::Card => "CARD",
            EntityKind::Ip => "IP",
            EntityKind::Url => "URL",
            EntityKind::Jwt => "JWT",
            EntityKind::ApiKey => "APIKEY",
            EntityKind::Token => "TOKEN",
            EntityKind::PrivateKey => "PRIVATEKEY",
            EntityKind::Term => "TERM",
            EntityKind::Bearer => "TOKEN",
        }
    }

    pub fn high_risk(self) -> bool {
        matches!(
            self,
            EntityKind::PrivateKey
                | EntityKind::ApiKey
                | EntityKind::Token
                | EntityKind::Card
                | EntityKind::Ssn
                | EntityKind::Bearer
                | EntityKind::Jwt
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedEntity {
    pub kind: EntityKind,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
    pub priority: u8,
    pub preview_masked: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMapping {
    pub token: String,
    pub value: String,
    pub entity_type: EntityKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: Uuid,
    pub session_tag: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub item_count: usize,
}
