use sqlx::{postgres::PgPoolOptions, PgPool, query_as, query_scalar, query, Row};
use tracing::{info, error};
use anyhow::Result;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::types::{Alert, Log};
    use crate::db::redis::RedisCache;
use crate::db::models::user::User;
use crate::db::models::rule::{DetectionRule, RuleCreate};
use crate::db::models::audit::AuditEvent;
use crate::db::models::compliance::TenantCompliancePolicy;
use crate::db::models::case::{CaseRecord, CasePlaybook, CaseTimelineEvent, CaseStatus};
use crate::db::cache::Cache;
use serde_json::Value;
use crate::auth::password::hash_password;

#[derive(sqlx::FromRow, Debug)]
struct DbAlert {
    id: Uuid,
    tenant_id: String,
    rule_id: String,
    rule_name: String,
    severity: String,
    description: String,
    source_ip: String,
    events: Value,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    status: String,
    events_count: i32,
}

impl DbAlert {
    fn into_alert(self) -> anyhow::Result<Alert> {
        let events: Vec<Log> = serde_json::from_value(self.events)
            .unwrap_or_default();

        Ok(Alert {
            id: self.id,
            tenant_id: self.tenant_id,
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

            match db.get_user_by_email("default", &email).await {
                Ok(Some(_)) => info!("Mock admin already exists: {}", email),
                Ok(None) => match hash_password(&password) {
                    Ok(hash) => match db.create_user("default", &email, &hash, role).await {
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
                    id, tenant_id, rule_id, rule_name, severity, description, source_ip,
                events, first_seen, last_seen, status, events_count,
                created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
        )
        .bind(alert.id)
            .bind(&alert.tenant_id)
        .bind(&alert.rule_id)
        .bind(&alert.rule_name)
        .bind(alert.severity.to_string())
        .bind(&alert.description)
        .bind(&alert.source_ip)
        .bind(serde_json::to_value(&alert.events)?)
        .bind(alert.first_seen)
        .bind(alert.last_seen)
        .bind(alert.status.to_string())
        .bind(alert.events_count as i32)
        .bind(alert.first_seen) // using first_seen as created_at placeholder
        .bind(alert.last_seen)  // same for updated_at
        .execute(&self.pool)
        .await?;
        
        info!("💾 Alert {} saved to database", alert.id);
        Ok(())
    }

    pub async fn create_log(&self, _log: &Log) -> Result<()> {
        // Raw log persistence has been moved to Elasticsearch. This
        // function was intentionally removed to avoid inserting logs
        // into Postgres. If code still calls this, return an error to
        // surface the callsite during testing.
        Err(anyhow::anyhow!("create_log removed: logs are indexed in Elasticsearch"))
    }

    pub async fn ping(&self) -> Result<()> {
        let _: (i32,) = query_as("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }
    
    pub async fn update_alert(&self, alert: &Alert, redis: Option<RedisCache>) -> Result<()> {
        // Fetch previous status to determine if active_alerts counter should change
        let prev_status: Option<String> = query_scalar(
            "SELECT status FROM alerts WHERE id = $1"
        )
        .bind(alert.id)
        .fetch_optional(&self.pool)
        .await?;
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
        .bind(alert.events_count as i32)
        .bind(alert.last_seen)
        .execute(&self.pool)
        .await?;
        // If previous status existed and transitioned from active -> non-active, decrement Redis counter
        if let Some(prev) = prev_status {
            let was_active = matches!(prev.as_str(), "NEW" | "INVESTIGATING");
            let now_active = matches!(alert.status.to_string().as_str(), "NEW" | "INVESTIGATING");
            if was_active && !now_active {
                if let Some(r) = redis {
                    let _ = r.decrement_counter("siem:stats:active_alerts").await;
                }
            }
        }

        Ok(())
    }
    
    #[allow(dead_code)]
    pub async fn get_alert(&self, tenant_id: &str, id: Uuid) -> Result<Option<Alert>> {
        let row: Option<DbAlert> = query_as(
            r#"SELECT id, tenant_id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count
               FROM alerts
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.into_alert()).transpose()
    }

    pub async fn get_open_alerts_by_ip(&self, tenant_id: &str, source_ip: &str) -> Result<Vec<Alert>> {
        let rows: Vec<DbAlert> = query_as(
            r#"SELECT id, tenant_id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count
               FROM alerts
               WHERE tenant_id = $1 AND source_ip = $2 AND status IN ('NEW', 'INVESTIGATING')
               ORDER BY last_seen DESC
               LIMIT 10"#,
        )
        .bind(tenant_id)
        .bind(source_ip)
        .fetch_all(&self.pool)
        .await?;

        let mut alerts = Vec::with_capacity(rows.len());
        for row in rows {
            alerts.push(row.into_alert()?);
        }
        Ok(alerts)
    }

    pub async fn get_open_alerts_by_ips(&self, tenant_id: &str, source_ips: &[String]) -> Result<Vec<Alert>> {
        if source_ips.is_empty() {
            return Ok(Vec::new());
        }

        let rows: Vec<DbAlert> = query_as(
            r#"SELECT id, tenant_id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count
               FROM alerts
               WHERE tenant_id = $1 AND source_ip = ANY($2) AND status IN ('NEW', 'INVESTIGATING')
               ORDER BY last_seen DESC
            "#,
        )
        .bind(tenant_id)
        .bind(source_ips)
        .fetch_all(&self.pool)
        .await?;

        let mut alerts = Vec::with_capacity(rows.len());
        for row in rows {
            alerts.push(row.into_alert()?);
        }
        Ok(alerts)
    }

    pub async fn create_alerts_batch(&self, alerts: &[Alert]) -> Result<()> {
        if alerts.is_empty() { return Ok(()); }

        // Build dynamic multi-row insert
        let mut idx = 1usize;
        let mut values_placeholders: Vec<String> = Vec::new();

        for _ in alerts.iter() {
            let placeholders = (0..14).map(|_| {
                let p = format!("${}", idx);
                idx += 1;
                p
            }).collect::<Vec<_>>().join(",");
            values_placeholders.push(format!("({})", placeholders));
        }

        let sql = format!(
            "INSERT INTO alerts (id, tenant_id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count, created_at, updated_at) VALUES {}",
            values_placeholders.join(",")
        );

        let mut q = sqlx::query(&sql);
        for a in alerts.iter() {
            q = q.bind(a.id)
                .bind(&a.tenant_id)
                .bind(&a.rule_id)
                .bind(&a.rule_name)
                .bind(a.severity.to_string())
                .bind(&a.description)
                .bind(&a.source_ip)
                .bind(serde_json::to_value(&a.events)?)
                .bind(a.first_seen)
                .bind(a.last_seen)
                .bind(a.status.to_string())
                .bind(a.events_count as i32)
                .bind(a.first_seen)
                .bind(a.last_seen);
        }

        q.execute(&self.pool).await?;
        Ok(())
    }

    /// Upsert a batch of alerts: insert new alerts or update existing ones in one statement.
    pub async fn upsert_alerts_batch(&self, alerts: &[Alert]) -> Result<()> {
        if alerts.is_empty() { return Ok(()); }

        // Build dynamic multi-row insert with ON CONFLICT DO UPDATE
        let mut idx = 1usize;
        let mut values_placeholders: Vec<String> = Vec::new();

        for _ in alerts.iter() {
            let placeholders = (0..14).map(|_| {
                let p = format!("${}", idx);
                idx += 1;
                p
            }).collect::<Vec<_>>().join(",");
            values_placeholders.push(format!("({})", placeholders));
        }

        let sql = format!(
            "INSERT INTO alerts (id, tenant_id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count, created_at, updated_at) VALUES {} ON CONFLICT (tenant_id, id) DO UPDATE SET last_seen = EXCLUDED.last_seen, status = EXCLUDED.status, events_count = EXCLUDED.events_count, events = EXCLUDED.events, updated_at = EXCLUDED.updated_at",
            values_placeholders.join(",")
        );

        let mut q = sqlx::query(&sql);
        for a in alerts.iter() {
            q = q.bind(a.id)
                .bind(&a.tenant_id)
                .bind(&a.rule_id)
                .bind(&a.rule_name)
                .bind(a.severity.to_string())
                .bind(&a.description)
                .bind(&a.source_ip)
                .bind(serde_json::to_value(&a.events)?)
                .bind(a.first_seen)
                .bind(a.last_seen)
                .bind(a.status.to_string())
                .bind(a.events_count as i32)
                .bind(a.first_seen)
                .bind(a.last_seen);
        }

        q.execute(&self.pool).await?;
        Ok(())
    }

    pub async fn get_recent_alerts(&self, tenant_id: &str, limit: i64) -> Result<Vec<Alert>> {
        let rows: Vec<DbAlert> = query_as(
            r#"SELECT id, tenant_id, rule_id, rule_name, severity, description, source_ip, events, first_seen, last_seen, status, events_count
               FROM alerts
               WHERE tenant_id = $1
               ORDER BY last_seen DESC
             LIMIT $2"#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut alerts = Vec::with_capacity(rows.len());
        for row in rows {
            alerts.push(row.into_alert()?);
        }
        Ok(alerts)
    }

    pub async fn get_stats(&self, tenant_id: &str) -> Result<(i64, i64, i64, i64)> {
        // Tenant-scoped stats snapshot. If the tenant row does not exist yet,
        // callers should treat this as an empty snapshot and seed it later.
        let row = query(
            "SELECT total_logs, total_alerts, active_alerts, critical_alerts FROM system_stats WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok((0, 0, 0, 0));
        };

        let total_logs: i64 = row.try_get("total_logs")?;
        let total_alerts: i64 = row.try_get("total_alerts")?;
        let active_alerts: i64 = row.try_get("active_alerts")?;
        let critical_alerts: i64 = row.try_get("critical_alerts")?;

        Ok((total_logs, total_alerts, active_alerts, critical_alerts))
    }

    /// Persist aggregated counters into a singleton `system_stats` row.
    pub async fn save_stats(&self, tenant_id: &str, total_logs: i64, total_alerts: i64, active_alerts: i64, critical_alerts: i64) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO system_stats (tenant_id, total_logs, total_alerts, active_alerts, critical_alerts, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (tenant_id) DO UPDATE
            SET total_logs = EXCLUDED.total_logs,
                total_alerts = EXCLUDED.total_alerts,
                active_alerts = EXCLUDED.active_alerts,
                critical_alerts = EXCLUDED.critical_alerts,
                updated_at = NOW();
            "#,
        )
        .bind(tenant_id)
        .bind(total_logs)
        .bind(total_alerts)
        .bind(active_alerts)
        .bind(critical_alerts)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_user(&self, tenant_id: &str, email: &str, password_hash: &str, role: &str) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (tenant_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, tenant_id, email, password_hash, role, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(role)
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_email(&self, tenant_id: &str, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, tenant_id, email, password_hash, role, created_at, updated_at FROM users WHERE tenant_id = $1 AND email = $2",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, tenant_id: &str, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, tenant_id, email, password_hash, role, created_at, updated_at FROM users WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn list_users_by_tenant(&self, tenant_id: &str) -> Result<Vec<User>> {
        let users = sqlx::query_as::<_, User>(
            "SELECT id, tenant_id, email, password_hash, role, created_at, updated_at FROM users WHERE tenant_id = $1 ORDER BY created_at ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    // Rules management
    pub async fn get_all_rules(&self, tenant_id: &str) -> Result<Vec<DetectionRule>> {
        let query = if tenant_id.is_empty() {
            "SELECT id, tenant_id, name, description, rule_type, severity, threshold, window_seconds, condition, is_enabled, created_at, updated_at FROM detection_rules"
        } else {
            "SELECT id, tenant_id, name, description, rule_type, severity, threshold, window_seconds, condition, is_enabled, created_at, updated_at FROM detection_rules WHERE tenant_id = $1"
        };

        let rules = if tenant_id.is_empty() {
            sqlx::query_as::<_, DetectionRule>(query).fetch_all(&self.pool).await?
        } else {
            sqlx::query_as::<_, DetectionRule>(query).bind(tenant_id).fetch_all(&self.pool).await?
        };

        Ok(rules)
    }

    pub async fn get_enabled_rules(&self, tenant_id: &str) -> Result<Vec<DetectionRule>> {
        let query = if tenant_id.is_empty() {
            "SELECT id, tenant_id, name, description, rule_type, severity, threshold, window_seconds, condition, is_enabled, created_at, updated_at FROM detection_rules WHERE is_enabled = true"
        } else {
            "SELECT id, tenant_id, name, description, rule_type, severity, threshold, window_seconds, condition, is_enabled, created_at, updated_at FROM detection_rules WHERE tenant_id = $1 AND is_enabled = true"
        };

        let rules = if tenant_id.is_empty() {
            sqlx::query_as::<_, DetectionRule>(query).fetch_all(&self.pool).await?
        } else {
            sqlx::query_as::<_, DetectionRule>(query).bind(tenant_id).fetch_all(&self.pool).await?
        };

        Ok(rules)
    }

    pub async fn create_rule(&self, rule: &RuleCreate) -> Result<DetectionRule> {
        let record = sqlx::query_as::<_, DetectionRule>(
            r#"
            INSERT INTO detection_rules (tenant_id, name, description, rule_type, severity, threshold, window_seconds, condition)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, tenant_id, name, description, rule_type, severity, threshold, window_seconds, condition, is_enabled, created_at, updated_at
            "#
        )
        .bind(&rule.tenant_id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(&rule.rule_type)
        .bind(&rule.severity)
        .bind(rule.threshold)
        .bind(rule.window_seconds)
        .bind(&rule.condition)
        .fetch_one(&self.pool)
        .await?;
        Ok(record)
    }

    pub async fn get_rule_by_id(&self, tenant_id: &str, id: Uuid) -> Result<Option<DetectionRule>> {
        let rule = sqlx::query_as::<_, DetectionRule>(
            "SELECT id, tenant_id, name, description, rule_type, severity, threshold, window_seconds, condition, is_enabled, created_at, updated_at FROM detection_rules WHERE tenant_id = $1 AND id = $2"
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(rule)
    }

    pub async fn update_rule(&self, tenant_id: &str, id: Uuid, update: crate::db::models::rule::RuleUpdate) -> Result<DetectionRule> {
        let existing = self.get_rule_by_id(tenant_id, id).await?.ok_or_else(|| anyhow::anyhow!("Rule not found"))?;
        
        let name = update.name.unwrap_or(existing.name);
        let description = update.description.or(existing.description);
        let severity = update.severity.unwrap_or(existing.severity);
        let threshold = update.threshold.or(existing.threshold);
        let window_seconds = update.window_seconds.or(existing.window_seconds);
        let condition = update.condition.or(existing.condition);
        let is_enabled = update.is_enabled.unwrap_or(existing.is_enabled);

        let record = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules 
            SET name = $1, description = $2, severity = $3, threshold = $4, window_seconds = $5, condition = $6, is_enabled = $7, updated_at = NOW()
            WHERE tenant_id = $8 AND id = $9
            RETURNING id, tenant_id, name, description, rule_type, severity, threshold, window_seconds, condition, is_enabled, created_at, updated_at
            "#
        )
        .bind(name)
        .bind(description)
        .bind(severity)
        .bind(threshold)
        .bind(window_seconds)
        .bind(condition)
        .bind(is_enabled)
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        Ok(record)
    }

    pub async fn delete_rule(&self, tenant_id: &str, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM detection_rules WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn latest_audit_hash(&self, tenant_id: &str) -> Result<Option<String>> {
        let hash = query_scalar(
            "SELECT event_hash FROM audit_events WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(hash)
    }

    pub async fn insert_audit_event(&self, event: &AuditEvent) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_events (
                id, tenant_id, actor_user_id, actor_email, actor_roles, action,
                resource_type, resource_id, target_tenant_id, request_id, metadata,
                previous_hash, event_hash, signature, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
        )
        .bind(event.id)
        .bind(&event.tenant_id)
        .bind(&event.actor_user_id)
        .bind(&event.actor_email)
        .bind(&event.actor_roles)
        .bind(&event.action)
        .bind(&event.resource_type)
        .bind(&event.resource_id)
        .bind(&event.target_tenant_id)
        .bind(&event.request_id)
        .bind(&event.metadata)
        .bind(&event.previous_hash)
        .bind(&event.event_hash)
        .bind(&event.signature)
        .bind(event.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_audit_events(&self, tenant_id: &str, limit: i64) -> Result<Vec<AuditEvent>> {
        let rows: Vec<AuditEvent> = query_as(
            r#"
            SELECT id, tenant_id, actor_user_id, actor_email, actor_roles, action, resource_type,
                   resource_id, target_tenant_id, request_id, metadata, previous_hash, event_hash,
                   signature, created_at
            FROM audit_events
            WHERE tenant_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn list_audit_events_since(&self, tenant_id: &str, since: DateTime<Utc>) -> Result<Vec<AuditEvent>> {
        let rows: Vec<AuditEvent> = query_as(
            r#"
            SELECT id, tenant_id, actor_user_id, actor_email, actor_roles, action, resource_type,
                   resource_id, target_tenant_id, request_id, metadata, previous_hash, event_hash,
                   signature, created_at
            FROM audit_events
            WHERE tenant_id = $1 AND created_at >= $2
            ORDER BY created_at DESC, id DESC
            "#,
        )
        .bind(tenant_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn purge_audit_events_before(&self, tenant_id: &str, cutoff: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM audit_events WHERE tenant_id = $1 AND created_at < $2",
        )
        .bind(tenant_id)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn purge_alerts_before(&self, tenant_id: &str, cutoff: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM alerts WHERE tenant_id = $1 AND created_at < $2",
        )
        .bind(tenant_id)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn get_tenant_compliance_policy(&self, tenant_id: &str) -> Result<TenantCompliancePolicy> {
        let policy = sqlx::query_as::<_, TenantCompliancePolicy>(
            r#"
            SELECT tenant_id, retention_days, legal_hold, legal_hold_reason, legal_hold_until,
                   access_review_interval_days, key_rotation_interval_days, last_key_rotation_at,
                   evidence_export_enabled, updated_at
            FROM tenant_compliance_policies
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(policy.unwrap_or_else(|| TenantCompliancePolicy::default_for_tenant(tenant_id)))
    }

    pub async fn upsert_tenant_compliance_policy(&self, policy: &TenantCompliancePolicy) -> Result<TenantCompliancePolicy> {
        let record = sqlx::query_as::<_, TenantCompliancePolicy>(
            r#"
            INSERT INTO tenant_compliance_policies (
                tenant_id, retention_days, legal_hold, legal_hold_reason, legal_hold_until,
                access_review_interval_days, key_rotation_interval_days, last_key_rotation_at,
                evidence_export_enabled, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            ON CONFLICT (tenant_id) DO UPDATE SET
                retention_days = EXCLUDED.retention_days,
                legal_hold = EXCLUDED.legal_hold,
                legal_hold_reason = EXCLUDED.legal_hold_reason,
                legal_hold_until = EXCLUDED.legal_hold_until,
                access_review_interval_days = EXCLUDED.access_review_interval_days,
                key_rotation_interval_days = EXCLUDED.key_rotation_interval_days,
                last_key_rotation_at = EXCLUDED.last_key_rotation_at,
                evidence_export_enabled = EXCLUDED.evidence_export_enabled,
                updated_at = NOW()
            RETURNING tenant_id, retention_days, legal_hold, legal_hold_reason, legal_hold_until,
                      access_review_interval_days, key_rotation_interval_days, last_key_rotation_at,
                      evidence_export_enabled, updated_at
            "#,
        )
        .bind(&policy.tenant_id)
        .bind(policy.retention_days)
        .bind(policy.legal_hold)
        .bind(&policy.legal_hold_reason)
        .bind(policy.legal_hold_until)
        .bind(policy.access_review_interval_days)
        .bind(policy.key_rotation_interval_days)
        .bind(policy.last_key_rotation_at)
        .bind(policy.evidence_export_enabled)
        .fetch_one(&self.pool)
        .await?;

        Ok(record)
    }

    pub async fn list_tenant_compliance_policies(&self) -> Result<Vec<TenantCompliancePolicy>> {
        let rows = query_as::<_, TenantCompliancePolicy>(
            r#"
            SELECT tenant_id, retention_days, legal_hold, legal_hold_reason, legal_hold_until,
                   access_review_interval_days, key_rotation_interval_days, last_key_rotation_at,
                   evidence_export_enabled, updated_at
            FROM tenant_compliance_policies
            ORDER BY tenant_id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    async fn ensure_default_case_playbooks(&self, tenant_id: &str) -> Result<()> {
        let existing: i64 = query_scalar("SELECT COUNT(*) FROM case_playbooks WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?;

        if existing > 0 {
            return Ok(());
        }

        let playbook_id = Uuid::new_v4();
        let now = Utc::now();
        let steps = serde_json::json!([
            {
                "title": "Confirm owner",
                "action_type": "assign",
                "description": "Assign the case to the on-call responder or analyst",
                "automated": false,
                "details": "Review the alert, then set ownership"
            },
            {
                "title": "Contain source",
                "action_type": "containment",
                "description": "Block or isolate the suspicious source until verified",
                "automated": false,
                "details": "Use firewall, EDR, or account controls"
            },
            {
                "title": "Capture evidence",
                "action_type": "collect",
                "description": "Attach logs, screenshots, and notes to the timeline",
                "automated": true,
                "details": "Use the case timeline for evidence preservation"
            }
        ]);

        sqlx::query(
            r#"
            INSERT INTO case_playbooks (
                id, tenant_id, name, description, severity, sla_minutes, escalate_after_minutes,
                steps, is_enabled, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9, $10)
            "#,
        )
        .bind(playbook_id)
        .bind(tenant_id)
        .bind("Default incident response")
        .bind("Triaged case path that links alert, ownership, escalation, and postmortem evidence.")
        .bind("HIGH")
        .bind(60_i32)
        .bind(120_i32)
        .bind(steps)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_case_playbooks(&self, tenant_id: &str) -> Result<Vec<CasePlaybook>> {
        self.ensure_default_case_playbooks(tenant_id).await?;

        let rows = query_as::<_, CasePlaybook>(
            r#"
            SELECT id, tenant_id, name, description, severity, sla_minutes, escalate_after_minutes,
                   steps, is_enabled, created_at, updated_at
            FROM case_playbooks
            WHERE tenant_id = $1
            ORDER BY is_enabled DESC, created_at ASC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn get_case_playbook(&self, tenant_id: &str, playbook_id: Uuid) -> Result<Option<CasePlaybook>> {
        let row = query_as::<_, CasePlaybook>(
            r#"
            SELECT id, tenant_id, name, description, severity, sla_minutes, escalate_after_minutes,
                   steps, is_enabled, created_at, updated_at
            FROM case_playbooks
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(playbook_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn list_cases(&self, tenant_id: &str) -> Result<Vec<CaseRecord>> {
        let rows = query_as::<_, CaseRecord>(
            r#"
            SELECT id, tenant_id, primary_alert_id, title, summary, severity, status, owner_user_id,
                   owner_email, playbook_id, sla_due_at, escalation_at, escalated_at, resolved_at,
                   outcome, postmortem_summary, created_at, updated_at
            FROM cases
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn get_case_by_id(&self, tenant_id: &str, case_id: Uuid) -> Result<Option<CaseRecord>> {
        let row = query_as::<_, CaseRecord>(
            r#"
            SELECT id, tenant_id, primary_alert_id, title, summary, severity, status, owner_user_id,
                   owner_email, playbook_id, sla_due_at, escalation_at, escalated_at, resolved_at,
                   outcome, postmortem_summary, created_at, updated_at
            FROM cases
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_case_by_alert_id(&self, tenant_id: &str, alert_id: Uuid) -> Result<Option<CaseRecord>> {
        let row = query_as::<_, CaseRecord>(
            r#"
            SELECT c.id, c.tenant_id, c.primary_alert_id, c.title, c.summary, c.severity, c.status,
                   c.owner_user_id, c.owner_email, c.playbook_id, c.sla_due_at, c.escalation_at,
                   c.escalated_at, c.resolved_at, c.outcome, c.postmortem_summary, c.created_at, c.updated_at
            FROM cases c
            LEFT JOIN case_alert_links l ON l.case_id = c.id AND l.tenant_id = c.tenant_id
            WHERE c.tenant_id = $1 AND (c.primary_alert_id = $2 OR l.alert_id = $2)
            ORDER BY c.created_at ASC
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(alert_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn list_case_alert_ids(&self, tenant_id: &str, case_id: Uuid) -> Result<Vec<Uuid>> {
        let rows = query_scalar::<_, Uuid>(
            "SELECT alert_id FROM case_alert_links WHERE tenant_id = $1 AND case_id = $2 ORDER BY created_at ASC",
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn list_case_timeline(&self, tenant_id: &str, case_id: Uuid) -> Result<Vec<CaseTimelineEvent>> {
        let rows = query_as::<_, CaseTimelineEvent>(
            r#"
            SELECT id, case_id, tenant_id, event_type, message, actor_user_id, actor_email, metadata, created_at
            FROM case_timeline_events
            WHERE tenant_id = $1 AND case_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn record_case_event(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        event_type: &str,
        message: &str,
        actor_user_id: Option<&str>,
        actor_email: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO case_timeline_events (
                id, case_id, tenant_id, event_type, message, actor_user_id, actor_email, metadata, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(case_id)
        .bind(tenant_id)
        .bind(event_type)
        .bind(message)
        .bind(actor_user_id)
        .bind(actor_email)
        .bind(metadata)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_case_from_alert(
        &self,
        alert: &Alert,
        owner_user_id: Option<&str>,
        owner_email: Option<&str>,
        title: Option<String>,
        summary: Option<String>,
        playbook_id: Option<Uuid>,
    ) -> Result<CaseRecord> {
        if let Some(existing) = self.get_case_by_alert_id(&alert.tenant_id, alert.id).await? {
            return Ok(existing);
        }

        self.ensure_default_case_playbooks(&alert.tenant_id).await?;

        let playbook = match playbook_id {
            Some(id) => self.get_case_playbook(&alert.tenant_id, id).await?,
            None => self.list_case_playbooks(&alert.tenant_id).await?.into_iter().find(|playbook| playbook.is_enabled),
        };

        let now = Utc::now();
        let (sla_minutes, escalate_after_minutes, assigned_playbook_id) = match playbook.as_ref() {
            Some(playbook) => (playbook.sla_minutes, playbook.escalate_after_minutes, Some(playbook.id)),
            None => (60, 120, None),
        };

        let case_id = Uuid::new_v4();
        let case_title = title.unwrap_or_else(|| format!("{} on {}", alert.rule_name, alert.source_ip));
        let case_summary = summary.unwrap_or_else(|| alert.description.clone());
        let severity = alert.severity.to_string();
        let status = CaseStatus::New.to_string();
        let sla_due_at = now + chrono::Duration::minutes(sla_minutes.max(1) as i64);
        let escalation_at = now + chrono::Duration::minutes(escalate_after_minutes.max(1) as i64);

        let record = sqlx::query_as::<_, CaseRecord>(
            r#"
            INSERT INTO cases (
                id, tenant_id, primary_alert_id, title, summary, severity, status,
                owner_user_id, owner_email, playbook_id, sla_due_at, escalation_at,
                escalated_at, resolved_at, outcome, postmortem_summary, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL, NULL, NULL, NULL, $13, $14)
            RETURNING id, tenant_id, primary_alert_id, title, summary, severity, status, owner_user_id,
                      owner_email, playbook_id, sla_due_at, escalation_at, escalated_at, resolved_at,
                      outcome, postmortem_summary, created_at, updated_at
            "#,
        )
        .bind(case_id)
        .bind(&alert.tenant_id)
        .bind(alert.id)
        .bind(case_title)
        .bind(case_summary)
        .bind(severity)
        .bind(status)
        .bind(owner_user_id)
        .bind(owner_email)
        .bind(assigned_playbook_id)
        .bind(sla_due_at)
        .bind(escalation_at)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO case_alert_links (case_id, alert_id, tenant_id, created_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (case_id, alert_id) DO NOTHING
            "#,
        )
        .bind(case_id)
        .bind(alert.id)
        .bind(&alert.tenant_id)
        .execute(&self.pool)
        .await?;

        let _ = self.record_case_event(
            &alert.tenant_id,
            case_id,
            "case.created",
            "Case created from incoming alert",
            owner_user_id,
            owner_email,
            serde_json::json!({
                "alert_id": alert.id,
                "playbook_id": assigned_playbook_id,
                "severity": alert.severity.to_string(),
            }),
        ).await;

        let _ = self.record_case_event(
            &alert.tenant_id,
            case_id,
            "alert.linked",
            "Primary alert linked to case",
            None,
            None,
            serde_json::json!({"alert_id": alert.id, "rule_id": alert.rule_id, "source_ip": alert.source_ip}),
        ).await;

        if let Some(playbook) = playbook {
            let _ = self.record_case_event(
                &alert.tenant_id,
                case_id,
                "playbook.assigned",
                &format!("Playbook '{}' assigned to case", playbook.name),
                None,
                None,
                serde_json::json!({
                    "playbook_id": playbook.id,
                    "playbook_name": playbook.name,
                    "steps": playbook.steps,
                }),
            ).await;
        }

        Ok(record)
    }

    pub async fn update_case(
        &self,
        tenant_id: &str,
        case_id: Uuid,
        status: Option<CaseStatus>,
        owner_user_id: Option<Option<String>>,
        owner_email: Option<Option<String>>,
        outcome: Option<Option<String>>,
        postmortem_summary: Option<Option<String>>,
    ) -> Result<CaseRecord> {
        let existing = self.get_case_by_id(tenant_id, case_id).await?.ok_or_else(|| anyhow::anyhow!("case not found"))?;

        let next_status = status.unwrap_or_else(|| existing.status.parse().unwrap_or(CaseStatus::New));
        let next_owner_user_id = owner_user_id.unwrap_or(existing.owner_user_id.clone());
        let next_owner_email = owner_email.unwrap_or(existing.owner_email.clone());
        let next_outcome = outcome.unwrap_or(existing.outcome.clone());
        let next_postmortem_summary = postmortem_summary.unwrap_or(existing.postmortem_summary.clone());
        let mut escalated_at = existing.escalated_at;
        let mut resolved_at = existing.resolved_at;

        if matches!(next_status, CaseStatus::Escalated) && escalated_at.is_none() {
            escalated_at = Some(Utc::now());
        }
        if matches!(next_status, CaseStatus::Resolved | CaseStatus::FalsePositive | CaseStatus::Closed | CaseStatus::Mitigated) && resolved_at.is_none() {
            resolved_at = Some(Utc::now());
        }

        let record = sqlx::query_as::<_, CaseRecord>(
            r#"
            UPDATE cases
            SET status = $1,
                owner_user_id = $2,
                owner_email = $3,
                outcome = $4,
                postmortem_summary = $5,
                escalated_at = $6,
                resolved_at = $7,
                updated_at = NOW()
            WHERE tenant_id = $8 AND id = $9
            RETURNING id, tenant_id, primary_alert_id, title, summary, severity, status, owner_user_id,
                      owner_email, playbook_id, sla_due_at, escalation_at, escalated_at, resolved_at,
                      outcome, postmortem_summary, created_at, updated_at
            "#,
        )
        .bind(next_status.to_string())
        .bind(&next_owner_user_id)
        .bind(&next_owner_email)
        .bind(&next_outcome)
        .bind(&next_postmortem_summary)
        .bind(escalated_at)
        .bind(resolved_at)
        .bind(tenant_id)
        .bind(case_id)
        .fetch_one(&self.pool)
        .await?;

        if existing.status != record.status {
            let _ = self.record_case_event(
                tenant_id,
                case_id,
                "case.status_changed",
                &format!("Case status changed from {} to {}", existing.status, record.status),
                next_owner_user_id.as_deref(),
                next_owner_email.as_deref(),
                serde_json::json!({"from": existing.status, "to": record.status}),
            ).await;
        }

        if existing.owner_user_id != record.owner_user_id || existing.owner_email != record.owner_email {
            let _ = self.record_case_event(
                tenant_id,
                case_id,
                "case.owner_changed",
                "Case ownership updated",
                next_owner_user_id.as_deref(),
                next_owner_email.as_deref(),
                serde_json::json!({"owner_user_id": record.owner_user_id, "owner_email": record.owner_email}),
            ).await;
        }

        Ok(record)
    }

    pub async fn escalate_overdue_cases(&self) -> Result<u64> {
        let overdue_cases = query_as::<_, CaseRecord>(
            r#"
            SELECT id, tenant_id, primary_alert_id, title, summary, severity, status, owner_user_id,
                   owner_email, playbook_id, sla_due_at, escalation_at, escalated_at, resolved_at,
                   outcome, postmortem_summary, created_at, updated_at
            FROM cases
            WHERE status IN ('NEW', 'INVESTIGATING', 'AWAITINGCUSTOMER')
              AND escalation_at IS NOT NULL
              AND escalation_at <= NOW()
              AND (status <> 'ESCALATED')
            ORDER BY escalation_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut escalated = 0_u64;
        for case_record in overdue_cases {
            let updated = self.update_case(
                &case_record.tenant_id,
                case_record.id,
                Some(CaseStatus::Escalated),
                None,
                None,
                None,
                None,
            ).await?;
            if updated.status == "ESCALATED" {
                escalated += 1;
            }
        }

        Ok(escalated)
    }

    pub async fn get_case_detail(&self, tenant_id: &str, case_id: Uuid) -> Result<Option<crate::db::models::case::CaseDetail>> {
        let Some(case_record) = self.get_case_by_id(tenant_id, case_id).await? else {
            return Ok(None);
        };

        let alerts = self.list_case_alert_ids(tenant_id, case_id).await?;
        let timeline = self.list_case_timeline(tenant_id, case_id).await?;
        let playbook = match case_record.playbook_id {
            Some(playbook_id) => self.get_case_playbook(tenant_id, playbook_id).await?,
            None => None,
        };

        Ok(Some(crate::db::models::case::CaseDetail {
            case_record,
            alerts,
            timeline,
            playbook,
        }))
    }
}

