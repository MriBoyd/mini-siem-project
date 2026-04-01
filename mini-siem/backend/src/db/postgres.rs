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
}

