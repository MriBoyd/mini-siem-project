'use client';

import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { AlertTriangle, ArrowUpRight, DollarSign, Loader2, Radio, Shield, SlidersHorizontal } from 'lucide-react';

import api from '@/lib/api';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { TenantCostDashboard, TenantDataCostPolicy, TenantDataCostPolicyUpdate } from '@/types';

type EditablePolicy = {
  daily_ingest_bytes_budget: string;
  hot_storage_bytes_budget: string;
  warm_storage_bytes_budget: string;
  cold_storage_bytes_budget: string;
  sampling_enabled: boolean;
  low_value_sampling_percent: string;
  high_value_sampling_percent: string;
  drop_low_value_when_over_budget: boolean;
};

function bytesToHuman(value: number) {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} GB`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} KB`;
  return `${value} B`;
}

function pressureLabel(pressure: number) {
  if (pressure >= 1.2) return 'critical';
  if (pressure >= 1.0) return 'at budget';
  if (pressure >= 0.75) return 'watch';
  return 'healthy';
}

export default function CostPage() {
  const queryClient = useQueryClient();
  const [policyForm, setPolicyForm] = useState<EditablePolicy>({
    daily_ingest_bytes_budget: '25000000000',
    hot_storage_bytes_budget: '10000000000',
    warm_storage_bytes_budget: '10000000000',
    cold_storage_bytes_budget: '5000000000',
    sampling_enabled: true,
    low_value_sampling_percent: '25',
    high_value_sampling_percent: '100',
    drop_low_value_when_over_budget: true,
  });

  const dashboardQuery = useQuery({
    queryKey: ['cost-dashboard'],
    queryFn: async () => (await api.get<TenantCostDashboard>('/cost/dashboard')).data,
    refetchInterval: 15_000,
  });

  const policyQuery = useQuery({
    queryKey: ['cost-policy'],
    queryFn: async () => (await api.get<TenantDataCostPolicy>('/cost/policy')).data,
    onSuccess: (policy) => {
      setPolicyForm({
        daily_ingest_bytes_budget: String(policy.daily_ingest_bytes_budget),
        hot_storage_bytes_budget: String(policy.hot_storage_bytes_budget),
        warm_storage_bytes_budget: String(policy.warm_storage_bytes_budget),
        cold_storage_bytes_budget: String(policy.cold_storage_bytes_budget),
        sampling_enabled: policy.sampling_enabled,
        low_value_sampling_percent: String(policy.low_value_sampling_percent),
        high_value_sampling_percent: String(policy.high_value_sampling_percent),
        drop_low_value_when_over_budget: policy.drop_low_value_when_over_budget,
      });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async () => {
      const payload: TenantDataCostPolicyUpdate = {
        daily_ingest_bytes_budget: Number(policyForm.daily_ingest_bytes_budget),
        hot_storage_bytes_budget: Number(policyForm.hot_storage_bytes_budget),
        warm_storage_bytes_budget: Number(policyForm.warm_storage_bytes_budget),
        cold_storage_bytes_budget: Number(policyForm.cold_storage_bytes_budget),
        sampling_enabled: policyForm.sampling_enabled,
        low_value_sampling_percent: Number(policyForm.low_value_sampling_percent),
        high_value_sampling_percent: Number(policyForm.high_value_sampling_percent),
        drop_low_value_when_over_budget: policyForm.drop_low_value_when_over_budget,
      };
      return (await api.put<TenantDataCostPolicy>('/cost/policy', payload)).data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cost-policy'] });
      queryClient.invalidateQueries({ queryKey: ['cost-dashboard'] });
    },
  });

  const dashboard = dashboardQuery.data;
  const policy = policyQuery.data || dashboard?.policy;

  useEffect(() => {
    if (policy) {
      setPolicyForm({
        daily_ingest_bytes_budget: String(policy.daily_ingest_bytes_budget),
        hot_storage_bytes_budget: String(policy.hot_storage_bytes_budget),
        warm_storage_bytes_budget: String(policy.warm_storage_bytes_budget),
        cold_storage_bytes_budget: String(policy.cold_storage_bytes_budget),
        sampling_enabled: policy.sampling_enabled,
        low_value_sampling_percent: String(policy.low_value_sampling_percent),
        high_value_sampling_percent: String(policy.high_value_sampling_percent),
        drop_low_value_when_over_budget: policy.drop_low_value_when_over_budget,
      });
    }
  }, [policy]);

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(2,132,199,0.1),_transparent_30%),linear-gradient(180deg,_#f8fafc_0%,_#ecfeff_45%,_#ffffff_100%)] p-6 text-slate-950 md:p-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <div className="flex flex-col gap-4 rounded-3xl border border-slate-200 bg-white/85 p-6 shadow-[0_20px_60px_rgba(15,23,42,0.08)] backdrop-blur md:flex-row md:items-start md:justify-between">
          <div className="max-w-3xl">
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-700">
              <DollarSign className="h-3.5 w-3.5" />
              Data-cost controls
            </div>
            <h1 className="text-4xl font-semibold tracking-tight">Predictable cost at scale.</h1>
            <p className="mt-3 text-base text-slate-600">
              Dynamic sampling, schema-aware drop rules, and storage tier budgets keep the ingest bill controlled by source, integration, and team.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="outline" asChild>
              <Link href="/dashboard">Dashboard</Link>
            </Button>
            <Button variant="outline" asChild>
              <Link href="/packs">Packs</Link>
            </Button>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-4">
          <Metric label="Tenant pressure" value={pressureLabel(dashboard?.tenant_budget_pressure || 0)} icon={<AlertTriangle className="h-4 w-4" />} />
          <Metric label="Usage today" value={bytesToHuman(dashboard?.usage_bytes_today || 0)} icon={<Radio className="h-4 w-4" />} />
          <Metric label="Sampled logs" value={String(dashboard?.sampled_logs_today || 0)} icon={<SlidersHorizontal className="h-4 w-4" />} />
          <Metric label="Dropped logs" value={String(dashboard?.dropped_logs_today || 0)} icon={<Shield className="h-4 w-4" />} />
        </div>

        <div className="grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
          <Card className="border-slate-200 shadow-[0_20px_60px_rgba(15,23,42,0.08)]">
            <CardHeader>
              <CardTitle>Policy</CardTitle>
              <CardDescription>Tenant budgets and automatic sampling thresholds.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Field label="Daily ingest budget" value={policyForm.daily_ingest_bytes_budget} onChange={(value) => setPolicyForm((current) => ({ ...current, daily_ingest_bytes_budget: value }))} />
                <Field label="Hot storage budget" value={policyForm.hot_storage_bytes_budget} onChange={(value) => setPolicyForm((current) => ({ ...current, hot_storage_bytes_budget: value }))} />
                <Field label="Warm storage budget" value={policyForm.warm_storage_bytes_budget} onChange={(value) => setPolicyForm((current) => ({ ...current, warm_storage_bytes_budget: value }))} />
                <Field label="Cold storage budget" value={policyForm.cold_storage_bytes_budget} onChange={(value) => setPolicyForm((current) => ({ ...current, cold_storage_bytes_budget: value }))} />
                <Field label="Low-value sampling %" value={policyForm.low_value_sampling_percent} onChange={(value) => setPolicyForm((current) => ({ ...current, low_value_sampling_percent: value }))} />
                <Field label="High-value sampling %" value={policyForm.high_value_sampling_percent} onChange={(value) => setPolicyForm((current) => ({ ...current, high_value_sampling_percent: value }))} />
              </div>

              <ToggleRow label="Sampling enabled" checked={policyForm.sampling_enabled} onChange={(checked) => setPolicyForm((current) => ({ ...current, sampling_enabled: checked }))} />
              <ToggleRow label="Drop low-value traffic over budget" checked={policyForm.drop_low_value_when_over_budget} onChange={(checked) => setPolicyForm((current) => ({ ...current, drop_low_value_when_over_budget: checked }))} />

              <Button className="w-full" onClick={() => updateMutation.mutate()} disabled={updateMutation.isPending}>
                {updateMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Save policy
              </Button>
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-[0_20px_60px_rgba(15,23,42,0.08)]">
            <CardHeader>
              <CardTitle>Top cost drivers</CardTitle>
              <CardDescription>Source, integration, and team views ranked by bytes.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <CostTable title="Sources" rows={dashboard?.top_sources || []} />
              <CostTable title="Integrations" rows={dashboard?.top_integrations || []} />
              <CostTable title="Teams" rows={dashboard?.top_teams || []} />
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <PressureCard label="Hot storage" pressure={dashboard?.hot_storage_pressure || 0} budget={policy?.hot_storage_bytes_budget || 0} />
          <PressureCard label="Warm storage" pressure={dashboard?.warm_storage_pressure || 0} budget={policy?.warm_storage_bytes_budget || 0} />
          <PressureCard label="Cold storage" pressure={dashboard?.cold_storage_pressure || 0} budget={policy?.cold_storage_bytes_budget || 0} />
        </div>

        <Card className="border-slate-200">
          <CardHeader>
            <CardTitle>Why it matters</CardTitle>
            <CardDescription>Packaged economics for 100k EPS environments.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 md:grid-cols-3">
            <InfoCard title="Dynamic sampling" text="Automatically backs off low-value traffic when the tenant crosses budget pressure thresholds." />
            <InfoCard title="Schema-aware drop rules" text="Drops heartbeat, metrics, and debug traffic before it inflates storage bills." />
            <InfoCard title="Budget visibility" text="Shows spend by source, integration, and team so procurement can forecast with confidence." />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Metric({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) {
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

function Field({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <Input value={value} onChange={(event) => onChange(event.target.value)} inputMode="numeric" />
    </div>
  );
}

function ToggleRow({ label, checked, onChange }: { label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <button type="button" className="flex w-full items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-left" onClick={() => onChange(!checked)}>
      <div>
        <div className="font-medium">{label}</div>
        <div className="text-sm text-slate-500">{checked ? 'Enabled' : 'Disabled'}</div>
      </div>
      <div className={`h-6 w-11 rounded-full p-1 transition ${checked ? 'bg-slate-950' : 'bg-slate-300'}`}>
        <div className={`h-4 w-4 rounded-full bg-white transition ${checked ? 'translate-x-5' : 'translate-x-0'}`} />
      </div>
    </button>
  );
}

function CostTable({ title, rows }: { title: string; rows: Array<{ key: string; bytes: number; logs: number; sampled: number; dropped: number }> }) {
  return (
    <div className="space-y-2">
      <div className="text-sm font-semibold uppercase tracking-[0.2em] text-slate-500">{title}</div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Dimension</TableHead>
            <TableHead>Bytes</TableHead>
            <TableHead>Logs</TableHead>
            <TableHead>Sampled</TableHead>
            <TableHead>Dropped</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={row.key}>
              <TableCell className="font-medium">{row.key}</TableCell>
              <TableCell>{bytesToHuman(row.bytes)}</TableCell>
              <TableCell>{row.logs}</TableCell>
              <TableCell>{row.sampled}</TableCell>
              <TableCell>{row.dropped}</TableCell>
            </TableRow>
          ))}
          {!rows.length ? (
            <TableRow>
              <TableCell colSpan={5} className="text-slate-500">No usage yet.</TableCell>
            </TableRow>
          ) : null}
        </TableBody>
      </Table>
    </div>
  );
}

function PressureCard({ label, pressure, budget }: { label: string; pressure: number; budget: number }) {
  const percent = Math.min(100, Math.round(pressure * 100));
  return (
    <Card className="border-slate-200">
      <CardContent className="space-y-3 p-5">
        <div className="flex items-center justify-between gap-3">
          <div className="font-medium">{label}</div>
          <Badge variant={pressure >= 1 ? 'destructive' : pressure >= 0.75 ? 'secondary' : 'default'}>{pressureLabel(pressure)}</Badge>
        </div>
        <div className="h-3 rounded-full bg-slate-200">
          <div className="h-3 rounded-full bg-slate-950" style={{ width: `${Math.min(100, percent)}%` }} />
        </div>
        <div className="text-sm text-slate-600">
          {bytesToHuman(Math.round(pressure * budget))} of {bytesToHuman(budget)}
        </div>
      </CardContent>
    </Card>
  );
}

function InfoCard({ title, text }: { title: string; text: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-center gap-2 font-medium">
        <ArrowUpRight className="h-4 w-4" /> {title}
      </div>
      <p className="mt-2 text-sm text-slate-600">{text}</p>
    </div>
  );
}