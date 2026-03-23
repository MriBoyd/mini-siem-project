use serde::{Serialize, Deserialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogTag {
    Auth,
    Network,
    Malware,
}

impl fmt::Display for LogTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogTag::Auth => write!(f, "auth"),
            LogTag::Network => write!(f, "network"),
            LogTag::Malware => write!(f, "malware"),
        }
    }
}

impl LogTag {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "auth" => Some(LogTag::Auth),
            "network" => Some(LogTag::Network),
            "malware" => Some(LogTag::Malware),
            _ => None,
        }
    }
}
