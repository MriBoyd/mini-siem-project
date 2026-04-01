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

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
}
