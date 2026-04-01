'use client';

import { useAuth } from '@/hooks/use-auth';
import { useQuery } from '@tanstack/react-query';
import api from '@/lib/api';
import { DashboardStats, Alert } from '@/types';
import useAlertsWS from '@/hooks/use-alerts-ws';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { LogOut, ShieldAlert, Activity, FileText, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

export default function DashboardPage() {
  const { user, logout } = useAuth();

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const response = await api.get<DashboardStats>('/dashboard/stats');
      return response.data;
    },
  });

  const { data: alerts, isLoading: alertsLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: async () => {
      const response = await api.get<Alert[]>('/alerts');
      return response.data;
    },
  });

  // subscribe to realtime alerts via WebSocket
  useAlertsWS();

  if (!user && !statsLoading) {
    // In a real app, we'd handle redirect in middleware or useAuth
  }

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold">Mini SIEM Dashboard</h1>
          <p className="text-muted-foreground">Welcome back, {user?.email}</p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="outline" asChild>
            <Link href="/cost">Cost</Link>
          </Button>
          <Button variant="outline" asChild>
            <Link href="/packs">Packs</Link>
          </Button>
          <Button variant="outline" asChild>
            <Link href="/cases">Cases</Link>
          </Button>
          <Button variant="outline" asChild>
            <Link href="/onboarding">Onboarding</Link>
          </Button>
          <Button variant="outline" onClick={() => logout()}>
            <LogOut className="mr-2 h-4 w-4" /> Logout
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard 
          title="Total Logs" 
          value={stats?.total_logs} 
          loading={statsLoading} 
          icon={<FileText className="h-4 w-4 text-muted-foreground" />} 
        />
        <StatCard 
          title="Total Alerts" 
          value={stats?.total_alerts} 
          loading={statsLoading} 
          icon={<ShieldAlert className="h-4 w-4 text-muted-foreground" />} 
        />
        <StatCard 
          title="Active Alerts" 
          value={stats?.active_alerts} 
          loading={statsLoading} 
          icon={<Activity className="h-4 w-4 text-muted-foreground" />} 
        />
        <StatCard 
          title="Critical Alerts" 
          value={stats?.critical_alerts} 
          loading={statsLoading} 
          icon={<AlertCircle className="h-4 w-4 text-destructive" />} 
          className="border-destructive/50"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Alerts</CardTitle>
        </CardHeader>
        <CardContent>
          {alertsLoading ? (
            <div className="space-y-2">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Rule</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>First Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {alerts?.map((alert) => (
                  <TableRow key={alert.id}>
                    <TableCell>
                      <Badge variant={getSeverityVariant(alert.severity)}>
                        {alert.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-medium">{alert.rule_name}</TableCell>
                    <TableCell>{alert.source_ip}</TableCell>
                    <TableCell>{alert.status}</TableCell>
                    <TableCell>{new Date(alert.first_seen).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function StatCard({ title, value, loading, icon, className }: any) {
  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-8 w-20" />
        ) : (
          <div className="text-2xl font-bold">{value?.toLocaleString() || 0}</div>
        )}
      </CardContent>
    </Card>
  );
}

function getSeverityVariant(severity: string): any {
  switch (severity) {
    case 'CRITICAL': return 'destructive';
    case 'HIGH': return 'destructive';
    case 'MEDIUM': return 'default';
    case 'LOW': return 'secondary';
    default: return 'outline';
  }
}
