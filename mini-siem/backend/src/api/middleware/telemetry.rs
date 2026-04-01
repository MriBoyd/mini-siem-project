use std::{future::{ready, Ready}, rc::Rc, sync::atomic::{AtomicU64, Ordering}, time::Instant};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::LocalBoxFuture;
use opentelemetry::global;
use opentelemetry::propagation::Extractor;
use opentelemetry::trace::TraceContextExt;
use tracing::{field, Instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

static IN_FLIGHT_HTTP_REQUESTS: AtomicU64 = AtomicU64::new(0);

pub struct RequestTelemetry;

impl<S, B> Transform<S, ServiceRequest> for RequestTelemetry
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestTelemetryMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestTelemetryMiddleware { service: Rc::new(service) }))
    }
}

pub struct RequestTelemetryMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestTelemetryMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let method = req.method().as_str().to_string();
        let route = normalize_route(req.path());
        let started = Instant::now();

        let parent_cx = global::get_text_map_propagator(|prop| prop.extract(&HeaderExtractor(req.headers())));
        let span = tracing::info_span!(
            "http.request",
            http.method = %method,
            http.route = %route,
            http.status_code = field::Empty,
            tenant_id = field::Empty,
            trace_id = field::Empty,
        );
        let _ = span.set_parent(parent_cx);

        Box::pin(async move {
            let inflight = IN_FLIGHT_HTTP_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
            metrics::gauge!("siem_http_inflight_requests", inflight as f64);

            let result = service.call(req).instrument(span.clone()).await;

            let remaining = IN_FLIGHT_HTTP_REQUESTS.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
            metrics::gauge!("siem_http_inflight_requests", remaining as f64);

            let status_code = result.as_ref().map(|response| response.status().as_u16()).unwrap_or(500);
            let status_class = format!("{}xx", status_code / 100);

            span.record("http.status_code", &status_code);
            let trace_id = span.context().span().span_context().trace_id().to_string();
            span.record("trace_id", &field::display(trace_id));

            metrics::counter!("siem_http_requests_total", 1, "method" => method.clone(), "route" => route.clone(), "status_class" => status_class.clone());
            metrics::histogram!("siem_http_request_duration_seconds", started.elapsed().as_secs_f64(), "method" => method.clone(), "route" => route.clone(), "status_class" => status_class.clone());

            if status_code >= 500 {
                metrics::counter!("siem_http_errors_total", 1, "route" => route.clone(), "status_class" => status_class.clone());
            }

            result
        })
    }
}

struct HeaderExtractor<'a>(&'a actix_web::http::header::HeaderMap);

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|key| key.as_str()).collect()
    }
}

fn normalize_route(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.is_empty() {
                ""
            } else if segment.chars().all(|c| c.is_ascii_digit()) || uuid::Uuid::parse_str(segment).is_ok() {
                ":id"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}