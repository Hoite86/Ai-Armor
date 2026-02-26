use core_model::{DetectedEntity, EntityKind, TokenMapping};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ProtectionOutput {
    pub session_id: Uuid,
    pub session_tag: String,
    pub protected_text: String,
    pub mappings: Vec<TokenMapping>,
    pub counts_by_type: HashMap<EntityKind, usize>,
}

pub fn session_tag(id: Uuid) -> String {
    let digest = Sha256::digest(id.as_bytes());
    let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &digest[..6]);
    encoded.chars().take(4).collect::<String>()
}

fn token_signature(session_id: Uuid, value: &str, kind: EntityKind, index: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(kind.token_label().as_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update(value.as_bytes());
    let out = hasher.finalize();
    let enc = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &out[..5]);
    enc.chars().take(4).collect()
}

pub fn protect_text(
    input: &str,
    entities: &[DetectedEntity],
    session_id: Uuid,
) -> ProtectionOutput {
    let tag = session_tag(session_id);
    let mut entities = entities.to_vec();
    entities.sort_by_key(|e| e.start);

    let mut out = String::with_capacity(input.len() + entities.len() * 8);
    let mut cursor = 0;
    let mut index_by_kind: HashMap<EntityKind, usize> = HashMap::new();
    let mut mappings = Vec::new();
    let mut counts = HashMap::new();

    for ent in entities {
        if ent.start < cursor || ent.end > input.len() {
            continue;
        }
        out.push_str(&input[cursor..ent.start]);
        let n = index_by_kind
            .entry(ent.kind)
            .and_modify(|v| *v += 1)
            .or_insert(1);
        let value = input[ent.start..ent.end].to_string();
        let sig = token_signature(session_id, &value, ent.kind, *n);
        let token = format!("[[{}:{}_{:02}_{}]]", tag, ent.kind.token_label(), *n, sig);
        mappings.push(TokenMapping {
            token: token.clone(),
            value,
            entity_type: ent.kind,
        });
        *counts.entry(ent.kind).or_insert(0) += 1;
        out.push_str(&token);
        cursor = ent.end;
    }
    out.push_str(&input[cursor..]);

    ProtectionOutput {
        session_id,
        session_tag: tag,
        protected_text: out,
        mappings,
        counts_by_type: counts,
    }
}

pub fn restore_text(input: &str, mappings: &[TokenMapping]) -> String {
    let mut out = input.to_string();
    let mut sorted = mappings.to_vec();
    sorted.sort_by_key(|m| std::cmp::Reverse(m.token.len()));
    for m in sorted {
        out = out.replace(&m.token, &m.value);
    }
    out
}

const MAX_EXTRACTED_TOKENS: usize = 512;

pub fn extract_tokens(input: &str) -> Vec<String> {
    let re = Regex::new(r"\[\[[A-Z0-9]{2,8}:[A-Z]+_\d{2}(?:_[A-Z0-9]{4})?\]\]").unwrap();
    re.find_iter(input)
        .take(MAX_EXTRACTED_TOKENS)
        .map(|m| m.as_str().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_detect::{detect_sensitive, DetectorConfig};

    #[test]
    fn round_trip() {
        let text = "email me at a@b.com";
        let ents = detect_sensitive(text, &DetectorConfig::default());
        let out = protect_text(text, &ents, Uuid::nil());
        let restored = restore_text(&out.protected_text, &out.mappings);
        assert_eq!(restored, text);
    }

    #[test]
    fn token_contains_signature_suffix() {
        let text = "user a@b.com";
        let ents = detect_sensitive(text, &DetectorConfig::default());
        let out = protect_text(text, &ents, Uuid::new_v4());
        assert!(out.protected_text.contains("_"));
        assert!(extract_tokens(&out.protected_text).len() >= 1);
    }

    #[test]
    fn token_extraction_is_capped() {
        let token = "[[AA1:EMAIL_01_ABCD]]";
        let text = std::iter::repeat(token)
            .take(600)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(extract_tokens(&text).len(), 512);
    }
}
