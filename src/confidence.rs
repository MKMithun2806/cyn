use crate::scanner::Evidence;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConfidenceLevel {
    Confirmed,
    Likely,
    Possible,
    Informational,
}

impl ConfidenceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::Likely => "LIKELY",
            Self::Possible => "POSSIBLE",
            Self::Informational => "INFORMATIONAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Confidence {
    pub score: u8,
    pub level: ConfidenceLevel,
    pub reasons: Vec<String>,
}

impl Default for Confidence {
    fn default() -> Self {
        Self {
            score: 0,
            level: ConfidenceLevel::Possible,
            reasons: vec!["Confidence was not calculated for this finding".into()],
        }
    }
}

pub fn assess(result_type: &str, evidence: &[Evidence]) -> Confidence {
    if result_type == "Log" {
        return Confidence {
            score: 100,
            level: ConfidenceLevel::Informational,
            reasons: vec!["Informational result; it is not a vulnerability claim".into()],
        };
    }

    let mut score = 0u16;
    let mut reasons = Vec::new();
    let kinds: HashSet<&str> = evidence.iter().map(|item| item.kind.as_str()).collect();
    for (kind, weight, reason) in [
        ("service", 20, "Service was confirmed on the target port"),
        ("product", 15, "Product identity was detected"),
        ("version", 25, "Version information was detected"),
        ("cpe", 25, "A CPE was detected for the service"),
        ("banner", 10, "A protocol banner supports the detection"),
        ("header", 10, "Protocol headers support the detection"),
        (
            "missing-header",
            15,
            "A missing security header was directly observed",
        ),
        ("result", 5, "The OpenVAS VT produced a result"),
    ] {
        if kinds.contains(kind) {
            score += weight;
            reasons.push(reason.into());
        }
    }

    let score = score.min(100) as u8;
    let level = match score {
        85..=100 => ConfidenceLevel::Confirmed,
        60..=84 => ConfidenceLevel::Likely,
        _ => ConfidenceLevel::Possible,
    };
    if reasons.is_empty() {
        reasons.push("No supporting service evidence was available".into());
    }
    Confidence {
        score,
        level,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(kind: &str) -> Evidence {
        Evidence {
            kind: kind.into(),
            source: "test".into(),
            value: "observed".into(),
        }
    }

    #[test]
    fn complete_evidence_is_confirmed() {
        let result = assess(
            "Alarm",
            &[
                evidence("service"),
                evidence("product"),
                evidence("version"),
                evidence("cpe"),
            ],
        );
        assert_eq!(result.score, 85);
        assert_eq!(result.level, ConfidenceLevel::Confirmed);
        assert_eq!(result.reasons.len(), 4);
    }

    #[test]
    fn partial_evidence_is_possible() {
        let result = assess("Alarm", &[evidence("result")]);
        assert_eq!(result.score, 5);
        assert_eq!(result.level, ConfidenceLevel::Possible);
    }

    #[test]
    fn logs_are_informational() {
        let result = assess("Log", &[]);
        assert_eq!(result.level, ConfidenceLevel::Informational);
        assert_eq!(result.score, 100);
    }
}
