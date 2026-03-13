use sqlx::{postgres::PgPoolOptions, PgPool, query, query_as, query_scalar};
use tracing::{info, error};
use anyhow::Result;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::types::{Alert, Log};
use serde_json::Value;

#[derive(sqlx::FromRow, Debug)]
struct DbAlert {
    id: Uuid,
    rule_id: String,
    rule_name: String,
    severity: String,
    description: String,
    source_ip: String,
    events: Value,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    status: String,
    events_count: i64,
}

impl DbAlert {
    fn into_alert(self) -> anyhow::Result<Alert> {
        let events: Vec<Log> = serde_json::from_value(self.events)
            .unwrap_or_default();

        Ok(Alert {
            id: self.id,
            rule_id: self.rule_id,
            rule_name: self.rule_name,
            severity: self.severity.parse().unwrap_or_else(|_| crate::types::AlertSeverity::Info),
            description: self.description,
            source_ip: self.source_ip,
            events,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            status: self.status.parse().unwrap_or_else(|_| crate::types::AlertStatus::New),
            events_count: self.events_count as usize,
        })
    }
}

pub struct PostgresDb {
    pool: PgPool,
}

impl PostgresDb {
    pub async fn new(database_url: &str) -> Result<Self> {
        info!("📦 Connecting to PostgreSQL...");
        
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await?;
        
        // Run migrations
        // run migrations from the db/migrations directory
        sqlx::migrate!("./src/db/migrations")
            .run(&pool)
            .await?;
        
        info!("✅ Connected to PostgreSQL");
        
        Ok(Self { pool })
    }
    
    pub async fn create_alert(&self, alert: &Alert) -> Result<()> {
        // direct use of Alert fields
        sqlx::query(
            r#"
            INSERT INTO alerts (
                id, rule_id, rule_name, severity, description, source_ip,
                events, first_seen, last_seen, status, events_count,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(alert.id)
        .bind(&alert.rule_id)
        .bind(&alert.rule_name)
        .bind(&alert.severity.to_string())
        .bind(&alert.description)
        .bind(&alert.source_ip)
        .bind(serde_json::to_value(&alert.events)?)
        .bind(alert.first_seen)
        .bind(alert.last_seen)
        .bind(&alert.status.to_string())
        .bind(alert.events_count as i64)
        .bind(alert.first_seen) // using first_seen as created_at placeholder
        .bind(alert.last_seen)  // same for updated_at
        .execute(&self.pool)
        .await?;
        
        info!("💾 Alert {} saved to database", alert.id);
        Ok(())
    }

    pub async fn create_log(&self, log: &Log) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO logs (
                id, timestamp, event_type, source_ip, target_user, service,
                message, severity, metadata, received_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(log.id)
        .bind(log.timestamp)
        .bind(&log.event_type)
        .bind(&log.source_ip)
        .bind(&log.target_user)
        .bind(&log.service)
        .bind(&log.message)
        .bind(&log.severity.to_string())
        .bind(&log.metadata)
        .bind(log.received_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
    
    pub async fn update_alert(&self, alert: &Alert) -> Result<()> {
        // update using Alert fields
        sqlx::query(
            r#"
            UPDATE alerts SET
                last_seen = $2,
                status = $3,
                events_count = $4,
                updated_at = $5
            WHERE id = $1
            "#,
        )
        .bind(alert.id)
        .bind(alert.last_seen)
        .bind(&alert.status.to_string())
        .bind(alert.events_count as i64)
        .bind(alert.last_seen)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    pub async fn get_alert(&self, id: Uuid) -> Result<Option<Alert>> {
        let row: Option<DbAlert> = query_as(
            r#"SELECT id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count
               FROM alerts
               WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_alert()).transpose()?)
    }

    pub async fn get_open_alerts_by_ip(&self, source_ip: &str) -> Result<Vec<Alert>> {
        let rows: Vec<DbAlert> = query_as(
            r#"SELECT id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count
               FROM alerts
               WHERE source_ip = $1 AND status IN ('NEW', 'INVESTIGATING')
               ORDER BY last_seen DESC
               LIMIT 10"#,
        )
        .bind(source_ip)
        .fetch_all(&self.pool)
        .await?;

        let mut alerts = Vec::with_capacity(rows.len());
        for row in rows {
            alerts.push(row.into_alert()?);
        }
        Ok(alerts)
    }

    pub async fn get_recent_alerts(&self, limit: i64) -> Result<Vec<Alert>> {
        let rows: Vec<DbAlert> = query_as(
            r#"SELECT id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count
               FROM alerts
               ORDER BY last_seen DESC
               LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut alerts = Vec::with_capacity(rows.len());
        for row in rows {
            alerts.push(row.into_alert()?);
        }
        Ok(alerts)
    }

    pub async fn get_stats(&self) -> Result<(i64, i64, i64, i64)> {
        let total_logs: i64 = query_scalar("SELECT COUNT(*) FROM logs")
            .fetch_one(&self.pool)
            .await?;
        let total_alerts: i64 = query_scalar("SELECT COUNT(*) FROM alerts")
            .fetch_one(&self.pool)
            .await?;
        let active_alerts: i64 = query_scalar(
            "SELECT COUNT(*) FROM alerts WHERE status IN ('NEW', 'INVESTIGATING')",
        )
        .fetch_one(&self.pool)
        .await?;
        let critical_alerts: i64 = query_scalar(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok((total_logs, total_alerts, active_alerts, critical_alerts))
    }
}

