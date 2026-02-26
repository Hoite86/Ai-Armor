use core_model::{DetectedEntity, EntityKind};
use once_cell::sync::Lazy;
use regex::Regex;

static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b").unwrap());
static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        (?<!\w)
        (?:\+?\d{1,3}[\s.-]?)?
        (?:\(?\d{2,4}\)?[\s.-]?)
        \d{3,4}[\s.-]?\d{4}
        (?!\w)
    ",
    )
    .unwrap()
});
static SSN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b").unwrap());
static CARD_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap());
static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b").unwrap()
});
static URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bhttps?://[a-zA-Z0-9.-]+(?:\:[0-9]{2,5})?(?:/[\w\-./?%&=+#:@~]*)?\b").unwrap()
});
static JWT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap()
});
static BEARER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._\-~+/]{16,}=*\b").unwrap());
static AWS_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b").unwrap());
static AWS_SECRET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[A-Za-z0-9/+=]{40}\b").unwrap());
static API_KEY_GENERIC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        \b(?:
            sk-[A-Za-z0-9]{20,}|              # OpenAI style
            gh[pousr]_[A-Za-z0-9]{20,}|       # GitHub tokens
            glpat-[A-Za-z0-9_-]{20,}|         # GitLab PAT
            xox[baprs]-[A-Za-z0-9-]{16,}|     # Slack tokens
            rk_live_[A-Za-z0-9]{20,}|         # Stripe restricted
            pk_live_[A-Za-z0-9]{20,}
        )\b
    ",
    )
    .unwrap()
});
static PK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
        .unwrap()
});
static HEX_TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b[a-fA-F0-9]{32,}\b").unwrap());

#[derive(Debug, Clone)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
    pub word_boundary: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct DetectorConfig {
    pub terms: Vec<String>,
    pub term_word_boundary: bool,
    pub custom_patterns: Vec<CustomPattern>,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            terms: vec![],
            term_word_boundary: true,
            custom_patterns: vec![],
        }
    }
}

pub fn detect_sensitive(text: &str, cfg: &DetectorConfig) -> Vec<DetectedEntity> {
    let mut out = Vec::new();
    push_matches(&mut out, text, &EMAIL_RE, EntityKind::Email, 0.95);
    push_matches(&mut out, text, &PHONE_RE, EntityKind::Phone, 0.72);
    push_matches(&mut out, text, &SSN_RE, EntityKind::Ssn, 0.96);

    for m in CARD_RE.find_iter(text) {
        let compact: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if (13..=19).contains(&compact.len()) && luhn_valid(&compact) {
            out.push(build_entity(
                EntityKind::Card,
                m.start(),
                m.end(),
                text,
                0.98,
            ));
        }
    }

    push_matches(&mut out, text, &IPV4_RE, EntityKind::Ip, 0.8);
    push_matches(&mut out, text, &URL_RE, EntityKind::Url, 0.62);
    push_matches(&mut out, text, &JWT_RE, EntityKind::Jwt, 0.9);
    push_matches(&mut out, text, &BEARER_RE, EntityKind::Bearer, 0.92);
    push_matches(&mut out, text, &AWS_ID_RE, EntityKind::ApiKey, 0.99);
    push_matches(&mut out, text, &API_KEY_GENERIC_RE, EntityKind::ApiKey, 0.9);

    for m in AWS_SECRET_RE.find_iter(text) {
        if entropy(m.as_str()) > 3.5 {
            out.push(build_entity(
                EntityKind::ApiKey,
                m.start(),
                m.end(),
                text,
                0.85,
            ));
        }
    }

    push_matches(&mut out, text, &PK_RE, EntityKind::PrivateKey, 1.0);

    for m in HEX_TOKEN_RE.find_iter(text) {
        if entropy(m.as_str()) > 3.2 {
            out.push(build_entity(
                EntityKind::Token,
                m.start(),
                m.end(),
                text,
                0.82,
            ));
        }
    }

    for (start, candidate) in token_spans(text) {
        if candidate.len() >= 24
            && candidate
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=_-.".contains(c))
            && entropy(candidate) > 4.0
        {
            out.push(build_entity(
                EntityKind::Token,
                start,
                start + candidate.len(),
                text,
                0.8,
            ));
        }
    }

    detect_terms(text, cfg, &mut out);
    detect_custom_patterns(text, cfg, &mut out);
    resolve_overlaps(out)
}

fn token_spans(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    for tok in text.split_whitespace() {
        if let Some(pos) = text[cursor..].find(tok) {
            let start = cursor + pos;
            out.push((start, tok));
            cursor = start + tok.len();
        }
    }
    out
}

fn detect_custom_patterns(text: &str, cfg: &DetectorConfig, out: &mut Vec<DetectedEntity>) {
    for p in &cfg.custom_patterns {
        if !p.enabled {
            continue;
        }
        if let Ok(re) = Regex::new(&p.regex) {
            for m in re.find_iter(text) {
                if p.word_boundary && !(is_boundary(text, m.start()) && is_boundary(text, m.end()))
                {
                    continue;
                }
                out.push(build_entity(
                    EntityKind::Term,
                    m.start(),
                    m.end(),
                    text,
                    0.8,
                ));
            }
        }
    }
}

pub fn suggest_regex_from_example(example: &str) -> String {
    let mut pattern = String::from("^");
    let mut chars = example.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() {
            let mut count = 1;
            while let Some(n) = chars.peek() {
                if n.is_ascii_digit() {
                    count += 1;
                    chars.next();
                } else {
                    break;
                }
            }
            pattern.push_str(&format!(r"\d{{{count}}}"));
        } else if ch.is_ascii_alphabetic() {
            let mut count = 1;
            while let Some(n) = chars.peek() {
                if n.is_ascii_alphabetic() {
                    count += 1;
                    chars.next();
                } else {
                    break;
                }
            }
            pattern.push_str(&format!(r"[A-Za-z]{{{count}}}"));
        } else {
            pattern.push_str(&regex::escape(&ch.to_string()));
        }
    }
    pattern.push('$');
    pattern
}

pub fn regex_matches_example(regex: &str, example: &str) -> bool {
    Regex::new(regex)
        .map(|r| r.is_match(example))
        .unwrap_or(false)
}

fn push_matches(
    out: &mut Vec<DetectedEntity>,
    text: &str,
    re: &Regex,
    kind: EntityKind,
    confidence: f32,
) {
    for m in re.find_iter(text) {
        if kind == EntityKind::Phone {
            let digits = m.as_str().chars().filter(|c| c.is_ascii_digit()).count();
            if digits < 10 {
                continue;
            }
        }
        out.push(build_entity(kind, m.start(), m.end(), text, confidence));
    }
}

fn detect_terms(text: &str, cfg: &DetectorConfig, out: &mut Vec<DetectedEntity>) {
    let hay = text.to_lowercase();
    for term in &cfg.terms {
        let needle = term.to_lowercase();
        let mut from = 0;
        while let Some(pos) = hay[from..].find(&needle) {
            let start = from + pos;
            let end = start + needle.len();
            let boundary_ok = if cfg.term_word_boundary {
                is_boundary(text, start) && is_boundary(text, end)
            } else {
                true
            };
            if boundary_ok {
                out.push(build_entity(EntityKind::Term, start, end, text, 0.75));
            }
            from = end;
        }
    }
}

fn is_boundary(text: &str, idx: usize) -> bool {
    let c = text.chars().nth(idx);
    match c {
        None => true,
        Some(ch) => !ch.is_ascii_alphanumeric() && ch != '_',
    }
}

fn build_entity(
    kind: EntityKind,
    start: usize,
    end: usize,
    text: &str,
    confidence: f32,
) -> DetectedEntity {
    let raw = &text[start..end];
    let preview_masked = if raw.len() <= 4 {
        "****".to_string()
    } else {
        format!("{}****{}", &raw[..2], &raw[raw.len() - 2..])
    };
    DetectedEntity {
        kind,
        start,
        end,
        confidence,
        priority: kind.priority(),
        preview_masked,
    }
}

pub fn resolve_overlaps(mut entities: Vec<DetectedEntity>) -> Vec<DetectedEntity> {
    entities.sort_by_key(|e| {
        (
            e.start,
            std::cmp::Reverse(e.priority),
            std::cmp::Reverse(e.end - e.start),
        )
    });
    let mut result: Vec<DetectedEntity> = Vec::new();
    for ent in entities {
        if let Some(last) = result.last_mut() {
            if ent.start < last.end {
                let ent_len = ent.end - ent.start;
                let last_len = last.end - last.start;
                let better = ent.priority > last.priority
                    || (ent.priority == last.priority && ent_len > last_len);
                if better {
                    *last = ent;
                }
                continue;
            }
        }
        result.push(ent);
    }
    result
}

pub fn entropy(s: &str) -> f32 {
    let mut counts = std::collections::HashMap::new();
    for b in s.bytes() {
        *counts.entry(b).or_insert(0usize) += 1;
    }
    let len = s.len() as f32;
    counts
        .values()
        .map(|c| {
            let p = *c as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn luhn_valid(num: &str) -> bool {
    let mut sum = 0;
    let mut alt = false;
    for ch in num.chars().rev() {
        let mut n = ch.to_digit(10).unwrap_or(0);
        if alt {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alt = !alt;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_credit_card_with_luhn() {
        let r = detect_sensitive("card 4111 1111 1111 1111", &DetectorConfig::default());
        assert!(r.iter().any(|e| e.kind == EntityKind::Card));
    }

    #[test]
    fn avoids_short_phone_false_positive() {
        let r = detect_sensitive("call 555-121", &DetectorConfig::default());
        assert!(!r.iter().any(|e| e.kind == EntityKind::Phone));
    }

    #[test]
    fn overlap_prefers_private_key() {
        let txt = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";
        let r = detect_sensitive(txt, &DetectorConfig::default());
        assert!(r.iter().any(|e| e.kind == EntityKind::PrivateKey));
    }

    #[test]
    fn detects_common_api_key_formats() {
        let txt = "token=ghp_abcdefghijklmnopqrstuvwxyz123456";
        let r = detect_sensitive(txt, &DetectorConfig::default());
        assert!(r.iter().any(|e| e.kind == EntityKind::ApiKey));
    }

    #[test]
    fn entropy_ordering() {
        assert!(entropy("AABBBBBBBBB") < entropy("aZ9+/KlmN8pqRstU"));
    }

    #[test]
    fn suggests_regex_and_matches_example() {
        let ex = "ABCD-1234";
        let re = suggest_regex_from_example(ex);
        assert!(regex_matches_example(&re, ex));
    }
}
