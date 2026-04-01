use anyhow::Result;
use lazy_static::lazy_static;
use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::{global, KeyValue};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{BatchConfigBuilder, BatchSpanProcessor, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

lazy_static! {
    static ref TENANT_LABELS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

static TENANT_LABEL_LIMIT: AtomicUsize = AtomicUsize::new(128);

pub struct ObservabilityGuard {
    tracer_provider: Option<SdkTracerProvider>,
}

impl ObservabilityGuard {
    pub fn shutdown(mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            let _ = provider.shutdown();
        }
    }
}

pub fn set_tenant_label_limit(limit: usize) {
    TENANT_LABEL_LIMIT.store(limit.max(1), Ordering::Relaxed);
}

pub fn bounded_tenant_label(tenant_id: &str) -> String {
    if let Some(existing) = TENANT_LABELS.lock().expect("tenant label mutex poisoned").get(tenant_id).cloned() {
        return existing;
    }

    let limit = TENANT_LABEL_LIMIT.load(Ordering::Relaxed).max(1);
    let mut labels = TENANT_LABELS.lock().expect("tenant label mutex poisoned");
    if let Some(existing) = labels.get(tenant_id).cloned() {
        return existing;
    }

    if labels.len() < limit {
        labels.insert(tenant_id.to_string(), tenant_id.to_string());
        return tenant_id.to_string();
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    tenant_id.hash(&mut hasher);
    format!("tenant_bucket_{:03}", (hasher.finish() as usize) % limit)
}

pub fn init_tracing(service_name: &str) -> Result<ObservabilityGuard> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:4317".to_string());
    let sample_ratio = std::env::var("OTEL_TRACES_SAMPLER_ARG")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(1.0)
        .clamp(0.0, 1.0);

    let batch_config = BatchConfigBuilder::default()
        .with_max_queue_size(
            std::env::var("OTEL_BSP_MAX_QUEUE_SIZE")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(2048),
        )
        .with_max_export_batch_size(
            std::env::var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(512),
        )
        .with_scheduled_delay(Duration::from_millis(
            std::env::var("OTEL_BSP_SCHEDULE_DELAY_MS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(5000),
        ))
        .build();

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(otlp_endpoint)
        .build()?;

    let resource = Resource::builder_empty()
        .with_attributes([KeyValue::new("service.name", service_name.to_string())])
        .build();

    let tracer_provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::TraceIdRatioBased(sample_ratio))
        .with_span_processor(
            BatchSpanProcessor::builder(exporter)
                .with_batch_config(batch_config)
                .build(),
        )
        .with_resource(resource)
        .build();

    global::set_tracer_provider(tracer_provider.clone());
    global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());

    let tracer = tracer_provider.tracer(service_name.to_string());
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(telemetry)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .compact(),
        )
        .try_init()?;

    Ok(ObservabilityGuard {
        tracer_provider: Some(tracer_provider),
    })
}

/// Initialize Prometheus exporter on the provided address (e.g. "0.0.0.0:9000").
pub fn init_metrics(listen_addr: &str) -> Result<()> {
    let addr: SocketAddr = listen_addr.parse()?;
    PrometheusBuilder::new()
        .set_buckets(&[
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
        ])?
        .with_http_listener(addr)
        .install()?;
    Ok(())
}

