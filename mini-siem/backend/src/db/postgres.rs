use sqlx::{postgres::PgPoolOptions, PgPool, query_as, query_scalar};
use tracing::{info, error};
use anyhow::Result;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::types::{Alert, Log};
use crate::db::models::user::User;
use crate::db::models::rule::{DetectionRule, RuleCreate};
use serde_json::Value;
use crate::auth::password::hash_password;

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
            severity: self.severity.parse().unwrap_or(crate::types::AlertSeverity::Info),
            description: self.description,
            source_ip: self.source_ip,
            events,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            status: self.status.parse().unwrap_or(crate::types::AlertStatus::New),
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
        
        let max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);

        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        
        // Run migrations
        // run migrations from the db/migrations directory
        sqlx::migrate!("./src/db/migrations")
            .run(&pool)
            .await?;

        info!("✅ Connected to PostgreSQL with pool size: {}", max_connections);

        // Prepare DB wrapper
        let db = Self { pool: pool.clone() };

        // Optional: seed a mock admin user for development/testing.
        // Controlled by the `SEED_MOCK_ADMIN` env var ("1" or "true").
        let seed = std::env::var("SEED_MOCK_ADMIN").ok()
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        if seed {
            let email = std::env::var("MOCK_ADMIN_EMAIL").unwrap_or_else(|_| "admin@example.com".to_string());
            let password = std::env::var("MOCK_ADMIN_PASSWORD").unwrap_or_else(|_| "password123".to_string());
            let role = "admin";

            match db.get_user_by_email(&email).await {
                Ok(Some(_)) => info!("Mock admin already exists: {}", email),
                Ok(None) => match hash_password(&password) {
                    Ok(hash) => match db.create_user(&email, &hash, role).await {
                        Ok(_) => info!("Seeded mock admin user: {}", email),
                        Err(e) => error!("Failed to create mock admin user: {}", e),
                    },
                    Err(e) => error!("Failed to hash mock admin password: {}", e),
                },
                Err(e) => error!("Error checking for existing mock admin: {}", e),
            }
        }

        Ok(db)
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
        .bind(alert.severity.to_string())
        .bind(&alert.description)
        .bind(&alert.source_ip)
        .bind(serde_json::to_value(&alert.events)?)
        .bind(alert.first_seen)
        .bind(alert.last_seen)
        .bind(alert.status.to_string())
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
        .bind(log.severity.to_string())
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
        .bind(alert.status.to_string())
        .bind(alert.events_count as i64)
        .bind(alert.last_seen)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    #[allow(dead_code)]
    pub async fn get_alert(&self, id: Uuid) -> Result<Option<Alert>> {
        let row: Option<DbAlert> = query_as(
            r#"SELECT id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count
               FROM alerts
               WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.into_alert()).transpose()
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

    pub async fn create_user(&self, email: &str, password_hash: &str, role: &str) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, password_hash, role, created_at, updated_at",
        )
        .bind(email)
        .bind(password_hash)
        .bind(role)
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, role, created_at, updated_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, role, created_at, updated_at FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    // Rules management
    pub async fn get_all_rules(&self) -> Result<Vec<DetectionRule>> {
        let rules = sqlx::query_as::<_, DetectionRule>(
            "SELECT id, name, description, rule_type, severity, threshold, window_seconds, is_enabled, created_at, updated_at FROM detection_rules"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rules)
    }

    pub async fn get_enabled_rules(&self) -> Result<Vec<DetectionRule>> {
        let rules = sqlx::query_as::<_, DetectionRule>(
            "SELECT id, name, description, rule_type, severity, threshold, window_seconds, is_enabled, created_at, updated_at FROM detection_rules WHERE is_enabled = true"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rules)
    }

    pub async fn create_rule(&self, rule: &RuleCreate) -> Result<DetectionRule> {
        let record = sqlx::query_as::<_, DetectionRule>(
            r#"
            INSERT INTO detection_rules (name, description, rule_type, severity, threshold, window_seconds)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, description, rule_type, severity, threshold, window_seconds, is_enabled, created_at, updated_at
            "#
        )
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(&rule.rule_type)
        .bind(&rule.severity)
        .bind(rule.threshold)
        .bind(rule.window_seconds)
        .fetch_one(&self.pool)
        .await?;
        Ok(record)
    }

    pub async fn get_rule_by_id(&self, id: Uuid) -> Result<Option<DetectionRule>> {
        let rule = sqlx::query_as::<_, DetectionRule>(
            "SELECT id, name, description, rule_type, severity, threshold, window_seconds, is_enabled, created_at, updated_at FROM detection_rules WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(rule)
    }

    pub async fn update_rule(&self, id: Uuid, update: crate::db::models::rule::RuleUpdate) -> Result<DetectionRule> {
        let existing = self.get_rule_by_id(id).await?.ok_or_else(|| anyhow::anyhow!("Rule not found"))?;
        
        let name = update.name.unwrap_or(existing.name);
        let description = update.description.or(existing.description);
        let severity = update.severity.unwrap_or(existing.severity);
        let threshold = update.threshold.or(existing.threshold);
        let window_seconds = update.window_seconds.or(existing.window_seconds);
        let is_enabled = update.is_enabled.unwrap_or(existing.is_enabled);

        let record = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules 
            SET name = $1, description = $2, severity = $3, threshold = $4, window_seconds = $5, is_enabled = $6, updated_at = NOW()
            WHERE id = $7
            RETURNING id, name, description, rule_type, severity, threshold, window_seconds, is_enabled, created_at, updated_at
            "#
        )
        .bind(name)
        .bind(description)
        .bind(severity)
        .bind(threshold)
        .bind(window_seconds)
        .bind(is_enabled)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        Ok(record)
    }

    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM detection_rules WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

