use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_logs: i64,
    pub total_alerts: i64,
    pub active_alerts: i64,
    pub critical_alerts: i64,
}

impl From<(i64, i64, i64, i64)> for DashboardStats {
    fn from(t: (i64, i64, i64, i64)) -> Self {
        Self {
            total_logs: t.0,
            total_alerts: t.1,
            active_alerts: t.2,
            critical_alerts: t.3,
        }
    }
}
