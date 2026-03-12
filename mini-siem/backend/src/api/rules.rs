#[derive(Debug, Deserialize)]
struct CreateRuleRequest {
    name: String,
    rule_type: RuleType,
    condition: serde_json::Value,
    severity: AlertSeverity,
    enabled: bool,
}

#[post("/api/v1/rules")]
async fn create_rule(
    req: web::Json<CreateRuleRequest>,
    db: web::Data<PostgresDb>,
) -> HttpResponse {
    // Store rule in database
    // Rules should be hot-reloadable
}

#[get("/api/v1/rules")]
async fn list_rules(db: web::Data<PostgresDb>) -> HttpResponse {
    // Return all rules with their status
}

#[put("/api/v1/rules/{id}/toggle")]
async fn toggle_rule(path: web::Path<Uuid>) -> HttpResponse {
    // Enable/disable a rule
}