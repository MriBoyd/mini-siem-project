// Lightweight Elasticsearch client using the REST API via `reqwest`.

use anyhow::Result;
use reqwest::Client;
use serde_json::Value;
use crate::types::Log;

#[derive(Clone)]
pub struct ElasticClient {
    client: Client,
    base_url: String,
}

impl ElasticClient {
    /// Create a new client for the given base URL (e.g. http://localhost:9200)
    pub async fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .build()?;

        let ec = ElasticClient {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        };

        // quick health check
        let _ = ec.health().await?;
        Ok(ec)
    }

    /// Check cluster health. Returns Ok(true) when reachable.
    pub async fn health(&self) -> Result<bool> {
        let url = format!("{}/_cluster/health", self.base_url);
        let res = self.client.get(&url).send().await?;
        if res.status().is_success() {
            Ok(true)
        } else {
            Err(anyhow::anyhow!("elasticsearch health check failed: {}", res.status()))
        }
    }

    /// Index a single log document into the given index name. Uses the log's UUID as the doc id.
    pub async fn index_log(&self, index: &str, log: &Log) -> Result<()> {
        let url = format!("{}/{}/_doc/{}?refresh=false", self.base_url, index, log.id);
        // Serialize the log and add an `@timestamp` field for Kibana/ES compatibility.
        let mut body = serde_json::to_value(log)?;
        if let Value::Object(map) = &mut body {
            map.insert("@timestamp".to_string(), serde_json::json!(log.timestamp.to_rfc3339()));
        }
        let res = self.client.post(&url).json(&body).send().await?;
        if res.status().is_success() {
            Ok(())
        } else {
            let status = res.status();
            let txt = res.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("failed to index log: {} - {}", status, txt))
        }
    }

    /// Bulk index logs into the provided index. Uses the Bulk API with NDJSON payload.
    /// Accepts a slice of `&Log` to avoid unnecessary cloning when callers hold `Arc<Log>`.
    pub async fn bulk_index(&self, index: &str, logs: &[&Log]) -> Result<()> {
        if logs.is_empty() {
            return Ok(());
        }

        let mut payload = String::new();
        for l in logs {
            let meta = serde_json::json!({ "index": { "_id": l.id.to_string() } });
            payload.push_str(&serde_json::to_string(&meta)?);
            payload.push('\n');
            // Serialize and inject `@timestamp` for consistency with mappings
            let mut doc = serde_json::to_value(&l)?;
            if let Value::Object(map) = &mut doc {
                map.insert("@timestamp".to_string(), serde_json::json!(l.timestamp.to_rfc3339()));
            }
            payload.push_str(&serde_json::to_string(&doc)?);
            payload.push('\n');
        }

        let url = format!("{}/{}/_bulk?refresh=false", self.base_url, index);
        let res = self.client.post(&url)
            .header("Content-Type", "application/x-ndjson")
            .body(payload)
            .send().await?;

        if res.status().is_success() {
            let v: Value = res.json().await.unwrap_or(Value::Null);
            // If there are any errors in bulk response, surface them
            if v.get("errors").and_then(|e| e.as_bool()).unwrap_or(false) {
                return Err(anyhow::anyhow!("bulk index reported errors: {}", v));
            }
            Ok(())
        } else {
            let status = res.status();
            let txt = res.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("bulk index failed: {} - {}", status, txt))
        }
    }

    /// Simple search wrapper. `query` should be a valid Elasticsearch query DSL object.
    /// Returns raw JSON response from Elasticsearch.
    pub async fn search(&self, index: &str, query: Value, from: usize, size: usize) -> Result<Value> {
        let url = format!("{}/{}/_search", self.base_url, index);
        let body = serde_json::json!({ "query": query, "from": from, "size": size });
        let res = self.client.post(&url).json(&body).send().await?;
        if res.status().is_success() {
            let v: Value = res.json().await?;
            Ok(v)
        } else {
            let status = res.status();
            let txt = res.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("search failed: {} - {}", status, txt))
        }
    }

    /// Delete an index (useful for tests / cleanup)
    pub async fn delete_index(&self, index: &str) -> Result<()> {
        let url = format!("{}/{}", self.base_url, index);
        let res = self.client.delete(&url).send().await?;
        if res.status().is_success() || res.status().as_u16() == 404 {
            Ok(())
        } else {
            let status = res.status();
            let txt = res.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("delete index failed: {} - {}", status, txt))
        }
    }

    /// Delete documents matching a query from the given index.
    pub async fn delete_by_query(&self, index: &str, query: Value) -> Result<()> {
        let url = format!("{}/{}/_delete_by_query?refresh=true", self.base_url, index);
        let body = serde_json::json!({ "query": query });
        let res = self.client.post(&url).json(&body).send().await?;
        if res.status().is_success() {
            Ok(())
        } else {
            let status = res.status();
            let txt = res.text().await.unwrap_or_default();
            Err(anyhow::anyhow!("delete_by_query failed: {} - {}", status, txt))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Log;
    use chrono::Utc;

    #[tokio::test]
    async fn create_client_and_check_health() {
        // This test is lightweight and will be ignored when no local ES is available.
        if std::env::var("CI").is_ok() {
            return;
        }
        let url = std::env::var("ELASTICSEARCH_HOST").unwrap_or_else(|_| "http://127.0.0.1:9200".to_string());
        let client = ElasticClient::new(&url).await;
        if client.is_err() {
            // skip when ES not reachable
            return;
        }
        let c = client.unwrap();
        let ok = c.health().await.unwrap_or(false);
        assert!(ok);
        // try indexing a synthetic doc (best-effort)
        let log = Log {
            id: uuid::Uuid::new_v4(),
            tenant_id: "tenant-test".into(),
            timestamp: Utc::now(),
            event_type: "test".into(),
            source_ip: "127.0.0.1".into(),
            target_user: None,
            service: None,
            message: "hello".into(),
            severity: crate::types::LogSeverity::Info,
            metadata: serde_json::Value::Null,
            received_at: Utc::now(),
        };
        let _ = c.index_log("mini-siem-logs-test", &log).await;
    }
}
