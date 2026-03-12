use sqlx::{postgres::PgPoolOptions, PgPool, query, query_as};
use tracing::{info, error};
use anyhow::Result;
use uuid::Uuid;

use crate::types::Alert;

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
                first_seen, last_seen, status, events_count,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(alert.id)
        .bind(&alert.rule_id)
        .bind(&alert.rule_name)
        .bind(&alert.severity.to_string())
        .bind(&alert.description)
        .bind(&alert.source_ip)
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
    
    pub async fn get_alert(&self, _id: Uuid) -> Result<Option<Alert>> {
        // not implemented
        Ok(None)
    }
    
    pub async fn get_open_alerts_by_ip(&self, _source_ip: &str) -> Result<Vec<Alert>> {
        Ok(Vec::new())
    }
    
    pub async fn get_recent_alerts(&self, _limit: i64) -> Result<Vec<Alert>> {
        Ok(Vec::new())
    }
}