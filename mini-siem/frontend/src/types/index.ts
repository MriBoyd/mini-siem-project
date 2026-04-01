export type UserRole = 'admin' | 'analyst' | 'user';

export interface User {
  id: string;
  email: string;
  role: UserRole;
  created_at?: string;
  updated_at?: string;
}

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type AlertStatus = 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSEPOSITIVE';

export interface Alert {
  id: string;
  tenant_id?: string;
  rule_id: string;
  rule_name: string;
  severity: AlertSeverity;
  description: string;
  source_ip: string;
  events: any[]; // We can refine this if needed
  first_seen: string;
  last_seen: string;
  status: AlertStatus;
  events_count: number;
}

export interface DetectionRule {
  id: string;
  name: string;
  description?: string;
  rule_type: string;
  severity: string;
  threshold?: number;
  window_seconds?: number;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DashboardStats {
  tenant_id?: string;
  total_logs: number;
  total_alerts: number;
  active_alerts: number;
  critical_alerts: number;
}

export type ServiceHealthStatus = 'healthy' | 'degraded' | 'down';

export interface ServiceHealth {
  status: ServiceHealthStatus;
  last_seen_at?: string | null;
  last_seen_seconds_ago?: number | null;
  details?: string | null;
}

export interface SystemHealth {
  status: ServiceHealthStatus;
  version: string;
  services: Record<string, ServiceHealth>;
}

export type CaseStatus = 'NEW' | 'INVESTIGATING' | 'AWAITINGCUSTOMER' | 'MITIGATED' | 'RESOLVED' | 'FALSEPOSITIVE' | 'ESCALATED' | 'CLOSED';

export interface CaseTimelineEvent {
  id: string;
  case_id: string;
  tenant_id: string;
  event_type: string;
  message: string;
  actor_user_id?: string | null;
  actor_email?: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface CasePlaybook {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  severity: string;
  sla_minutes: number;
  escalate_after_minutes: number;
  steps: Array<Record<string, unknown>>;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CaseRecord {
  id: string;
  tenant_id: string;
  primary_alert_id: string;
  title: string;
  summary: string;
  severity: string;
  status: CaseStatus;
  owner_user_id?: string | null;
  owner_email?: string | null;
  playbook_id?: string | null;
  sla_due_at?: string | null;
  escalation_at?: string | null;
  escalated_at?: string | null;
  resolved_at?: string | null;
  outcome?: string | null;
  postmortem_summary?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CaseDetail {
  case_record: CaseRecord;
  alerts: string[];
  timeline: CaseTimelineEvent[];
  playbook?: CasePlaybook | null;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
}
