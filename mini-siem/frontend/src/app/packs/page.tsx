'use client';

import { type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertTriangle, BookOpenCheck, Boxes, Cloud, Laptop, Loader2, Users } from 'lucide-react';

import api from '@/lib/api';
import { DetectionPack } from '@/types';

const packIcons: Record<string, ReactNode> = {
  'Cloud IAM Abuse': <Cloud className="h-4 w-4" />,
  'Endpoint Ransomware Precursors': <Laptop className="h-4 w-4" />,
  'Insider Risk': <Users className="h-4 w-4" />,
};

function titleCaseKey(value: string) {
  return value.replace(/[_-]/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function DetectionPacksPage() {
  const queryClient = useQueryClient();

  const packsQuery = useQuery({
    queryKey: ['detection-packs'],
    queryFn: async () => (await api.get<DetectionPack[]>('/detection-packs')).data,
    refetchInterval: 30_000,
  });

  const installMutation = useMutation({
    mutationFn: async (slug: string) => (await api.post<DetectionPack>(`/detection-packs/${slug}/install`, {})).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detection-packs'] });
      queryClient.invalidateQueries({ queryKey: ['rules'] });
    },
  });

  const packs = packsQuery.data || [];

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(15,23,42,0.08),_transparent_30%),linear-gradient(180deg,_#f8fafc_0%,_#eef2ff_45%,_#ffffff_100%)] p-6 text-slate-950 md:p-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <div className="flex flex-col gap-4 rounded-3xl border border-slate-200 bg-white/85 p-6 shadow-[0_20px_60px_rgba(15,23,42,0.08)] backdrop-blur md:flex-row md:items-start md:justify-between">
          <div className="max-w-3xl">
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-indigo-700">
              <Boxes className="h-3.5 w-3.5" />
              Curated detection packs
            </div>
            <h1 className="text-4xl font-semibold tracking-tight">Packaged expertise for high-demand incidents.</h1>
            <p className="mt-3 text-base text-slate-600">
              Install validated rules, enrichment hints, and response playbooks for cloud IAM abuse, ransomware precursors, and insider risk in one click.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="outline" asChild>
              <Link href="/dashboard">Dashboard</Link>
            </Button>
            <Button variant="outline" asChild>
              <Link href="/cases">Cases</Link>
            </Button>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <Metric label="Packages" value={String(packs.length || 3)} icon={<Boxes className="h-4 w-4" />} />
          <Metric label="Validated rules" value={String(packs.reduce((total, pack) => total + pack.total_rule_count, 0))} icon={<BookOpenCheck className="h-4 w-4" />} />
          <Metric label="Ready for install" value={String(packs.filter((pack) => !pack.installed).length)} icon={<AlertTriangle className="h-4 w-4" />} />
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          {(packsQuery.isLoading ? Array.from({ length: 3 }) : packs).map((entry, index) => {
            if (packsQuery.isLoading) {
              return <Card key={index} className="h-96 animate-pulse border-slate-200 bg-white/80" />;
            }

            const pack = entry as DetectionPack;
            const Icon = packIcons[pack.vertical] || <Boxes className="h-4 w-4" />;

            return (
              <Card key={pack.slug} className="overflow-hidden border-slate-200 shadow-[0_20px_60px_rgba(15,23,42,0.08)]">
                <CardHeader className="border-b bg-slate-950 text-white">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-white/80">
                        {Icon}
                        {pack.vertical}
                      </div>
                      <CardTitle className="text-white">{pack.name}</CardTitle>
                      <CardDescription className="mt-1 text-slate-300">{pack.description}</CardDescription>
                    </div>
                    <Badge variant={pack.installed ? 'default' : 'secondary'} className={pack.installed ? 'bg-emerald-500 text-white' : 'bg-white/10 text-white'}>
                      {pack.installed ? 'Installed' : 'Ready'}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-5 p-5">
                  <div className="flex flex-wrap gap-2 text-xs text-slate-600">
                    <Badge variant="secondary">{pack.installed_rule_count}/{pack.total_rule_count} rules installed</Badge>
                    <Badge variant="outline">Validated</Badge>
                  </div>

                  <div className="space-y-2">
                    <div className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-500">Validated rules</div>
                    <div className="space-y-2">
                      {pack.rules.map((rule) => (
                        <div key={rule.name} className="rounded-2xl border border-slate-200 bg-slate-50 p-3">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="text-sm font-semibold">{rule.name}</div>
                              <div className="text-xs text-slate-500">{rule.description}</div>
                            </div>
                            <Badge variant={rule.validated ? 'default' : 'outline'}>{rule.validated ? 'Validated' : 'Draft'}</Badge>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2 text-[11px] uppercase tracking-[0.15em] text-slate-500">
                            <Badge variant="secondary">{titleCaseKey(rule.rule_type)}</Badge>
                            <Badge variant="outline">{rule.severity}</Badge>
                            {rule.threshold !== null && rule.threshold !== undefined ? <Badge variant="outline">threshold {rule.threshold}</Badge> : null}
                            {rule.window_seconds ? <Badge variant="outline">window {rule.window_seconds}s</Badge> : null}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="h-px w-full bg-slate-200" />

                  <div className="space-y-2">
                    <div className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-500">Enrichment</div>
                    <div className="rounded-2xl border border-slate-200 bg-white p-3 text-sm text-slate-600">
                      {Object.entries(pack.enrichment).map(([key, value]) => (
                        <div key={key} className="mb-2 last:mb-0">
                          <span className="font-medium text-slate-900">{titleCaseKey(key)}:</span>{' '}
                          {Array.isArray(value) ? value.join(', ') : String(value)}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-500">Response playbook</div>
                    <div className="space-y-2">
                      {pack.playbook.map((step, stepIndex) => (
                        <div key={`${pack.slug}-${stepIndex}`} className="rounded-2xl border border-slate-200 bg-white p-3 text-sm">
                          <div className="flex items-center justify-between gap-3">
                            <div className="font-medium">{step.title}</div>
                            <Badge variant={step.automated ? 'default' : 'outline'}>{step.automated ? 'Automated' : step.owner_role}</Badge>
                          </div>
                          <div className="mt-1 text-slate-600">{step.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <Button
                    className="w-full"
                    onClick={() => installMutation.mutate(pack.slug)}
                    disabled={installMutation.isPending && installMutation.variables === pack.slug}
                  >
                    {installMutation.isPending && installMutation.variables === pack.slug ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                    {pack.installed ? 'Reinstall / sync' : 'Install pack'}
                  </Button>
                </CardContent>
              </Card>
            );
          })}
        </div>
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