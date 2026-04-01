'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import type { ReactNode } from 'react';
import { Activity, AlertTriangle, ArrowUpRight, Gauge, Loader2, ShieldCheck, Sparkles, ShieldAlert } from 'lucide-react';

import api from '@/lib/api';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ReliabilityOverview, ReliabilityReportRecord } from '@/types';

function fmtMs(value: number) {
  return `${value.toFixed(1)} ms`;
}

function fmtPercent(value: number) {
  return `${value.toFixed(2)}%`;
}

function statusVariant(status: string) {
  if (status === 'healthy' || status === 'passed') return 'default';
  if (status === 'degraded') return 'secondary';
  return 'destructive';
}

export default function ReliabilityPage() {
  const queryClient = useQueryClient();

  const overviewQuery = useQuery({
    queryKey: ['reliability-overview'],
    queryFn: async () => (await api.get<ReliabilityOverview>('/reliability/overview')).data,
    refetchInterval: 30_000,
  });

  const replayMutation = useMutation({
    mutationFn: async () => (await api.post<ReliabilityReportRecord>('/reliability/drills/replay', {})).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reliability-overview'] });
    },
  });

  const chaosMutation = useMutation({
    mutationFn: async () => (await api.post<ReliabilityReportRecord>('/reliability/drills/chaos', {})).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reliability-overview'] });
    },
  });

  const overview = overviewQuery.data;
  const snapshot = overview?.snapshot;
  const reports = overview?.recent_reports || [];

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(37,99,235,0.12),_transparent_32%),linear-gradient(180deg,_#eff6ff_0%,_#f8fafc_42%,_#ffffff_100%)] p-6 text-slate-950 md:p-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <div className="flex flex-col gap-4 rounded-3xl border border-slate-200 bg-white/85 p-6 shadow-[0_20px_60px_rgba(15,23,42,0.08)] backdrop-blur md:flex-row md:items-start md:justify-between">
          <div className="max-w-3xl">
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-blue-700">
              <Gauge className="h-3.5 w-3.5" />
              Reliability proofs
            </div>
            <h1 className="text-4xl font-semibold tracking-tight">Measured SLOs, replay drills, and chaos reports.</h1>
            <p className="mt-3 text-base text-slate-600">
              This page shows live ingest availability, detection latency p95/p99, alert delivery latency, and the latest drill reports that prove the system still works under stress.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="outline" asChild>
              <Link href="/dashboard">Dashboard</Link>
            </Button>
            <Button onClick={() => replayMutation.mutate()} disabled={replayMutation.isPending}>
              {replayMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Sparkles className="mr-2 h-4 w-4" />}
              Run replay drill
            </Button>
            <Button variant="outline" onClick={() => chaosMutation.mutate()} disabled={chaosMutation.isPending}>
              {chaosMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldAlert className="mr-2 h-4 w-4" />}
              Run chaos drill
            </Button>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-4">
          <Metric label="Ingest availability" value={snapshot ? fmtPercent(snapshot.ingest_availability_observed_percent) : '—'} icon={<ShieldCheck className="h-4 w-4" />} />
          <Metric label="Detection p95" value={snapshot ? fmtMs(snapshot.detection_latency_p95_ms) : '—'} icon={<Activity className="h-4 w-4" />} />
          <Metric label="Alert delivery p95" value={snapshot ? fmtMs(snapshot.alert_delivery_latency_p95_ms) : '—'} icon={<ArrowUpRight className="h-4 w-4" />} />
          <Metric label="Samples" value={snapshot ? String(snapshot.sample_count) : '—'} icon={<AlertTriangle className="h-4 w-4" />} />
        </div>

        <div className="grid gap-6 lg:grid-cols-[0.95fr_1.05fr]">
          <Card className="border-slate-200 shadow-[0_20px_60px_rgba(15,23,42,0.08)]">
            <CardHeader>
              <CardTitle>SLO snapshot</CardTitle>
              <CardDescription>Targets versus live measurements from the rolling reliability sample window.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {overviewQuery.isLoading ? (
                <div className="space-y-3">
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                </div>
              ) : snapshot ? (
                <div className="space-y-3">
                  <SloRow label="Ingest availability" target={fmtPercent(snapshot.ingest_availability_target_percent)} value={fmtPercent(snapshot.ingest_availability_observed_percent)} />
                  <SloRow label="Detection latency p95" target={fmtMs(snapshot.detection_latency_target_p95_ms)} value={fmtMs(snapshot.detection_latency_p95_ms)} />
                  <SloRow label="Detection latency p99" target="n/a" value={fmtMs(snapshot.detection_latency_p99_ms)} />
                  <SloRow label="Alert delivery p95" target={fmtMs(snapshot.alert_delivery_latency_target_p95_ms)} value={fmtMs(snapshot.alert_delivery_latency_p95_ms)} />
                  <SloRow label="Alert delivery p99" target="n/a" value={fmtMs(snapshot.alert_delivery_latency_p99_ms)} />
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium">Overall status</div>
                      <Badge variant={statusVariant(snapshot.status) as any}>{snapshot.status}</Badge>
                    </div>
                  </div>
                </div>
              ) : null}
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-[0_20px_60px_rgba(15,23,42,0.08)]">
            <CardHeader>
              <CardTitle>Weekly proof trail</CardTitle>
              <CardDescription>Replay and chaos reports are stored with timestamps and drill summaries.</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Drill</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reports.map((report) => (
                    <TableRow key={report.id}>
                      <TableCell className="font-medium">{report.report_type}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(report.status) as any}>{report.status}</Badge>
                      </TableCell>
                      <TableCell>{report.duration_ms} ms</TableCell>
                      <TableCell>{new Date(report.created_at).toLocaleString()}</TableCell>
                    </TableRow>
                  ))}
                  {!reports.length ? (
                    <TableRow>
                      <TableCell colSpan={4} className="text-slate-500">
                        No reliability reports yet. Run a drill to create the first proof record.
                      </TableCell>
                    </TableRow>
                  ) : null}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>

        <Card className="border-slate-200">
          <CardHeader>
            <CardTitle>Why it matters</CardTitle>
            <CardDescription>Measured reliability is easier to trust than architecture claims.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 md:grid-cols-3">
            <ProofCard title="Public SLOs" text="Shows ingest availability plus detection and alert delivery latency at the page level, not in a deck." />
            <ProofCard title="Weekly drills" text="Replay and chaos drill endpoints create timestamped proof records that can be reviewed after each run." />
            <ProofCard title="Operational evidence" text="The rolling sample window gives procurement and engineering a shared view of what the system actually delivered." />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Metric({ label, value, icon }: { label: string; value: string; icon: ReactNode }) {
  return (
    <Card className="border-slate-200 bg-white shadow-[0_12px_35px_rgba(15,23,42,0.06)]">
      <CardContent className="flex items-center justify-between p-5">
        <div>
          <div className="text-xs uppercase tracking-[0.2em] text-slate-500">{label}</div>
          <div className="mt-2 text-2xl font-semibold text-slate-950">{value}</div>
        </div>
        <div className="rounded-2xl bg-slate-950 p-3 text-white">{icon}</div>
      </CardContent>
    </Card>
  );
}

function SloRow({ label, target, value }: { label: string; target: string; value: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="font-medium">{label}</div>
          <div className="text-sm text-slate-500">Target {target}</div>
        </div>
        <div className="text-right text-sm font-semibold text-slate-950">{value}</div>
      </div>
    </div>
  );
}

function ProofCard({ title, text }: { title: string; text: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-center gap-2 font-medium">
        <ArrowUpRight className="h-4 w-4" /> {title}
      </div>
      <p className="mt-2 text-sm text-slate-600">{text}</p>
    </div>
  );
}