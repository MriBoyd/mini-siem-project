'use client';

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { CheckCircle2, Circle, Copy, Loader2, Rocket, ShieldCheck, Sparkles, Activity, Server, Radio } from 'lucide-react';

import api from '@/lib/api';
import useAlertsWS from '@/hooks/use-alerts-ws';
import { useAuth } from '@/hooks/use-auth';
import { Alert, DetectionRule, SystemHealth } from '@/types';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';

type ReplayLog = {
  event_type: string;
  source_ip: string;
  target_user: string | null;
  service: string | null;
  message: string;
  severity: 'INFO';
  timestamp: string;
};

const onboardingSteps = [
  {
    title: 'Connect the agent',
    description: 'Point the file or syslog collector at this backend and verify the first heartbeat.',
    icon: Server,
  },
  {
    title: 'Replay test data',
    description: 'Send a small failed-login burst to exercise ingest, Kafka, indexer, and alerting.',
    icon: Radio,
  },
  {
    title: 'Confirm detections',
    description: 'Use the prebuilt rules already present in the system to confirm coverage.',
    icon: ShieldCheck,
  },
  {
    title: 'Validate the first alert',
    description: 'Wait for the first alert to land, then mark the workspace ready for rollout.',
    icon: Sparkles,
  },
] as const;

function buildReplayLogs(): ReplayLog[] {
  const sourceIp = '203.0.113.77';
  const timestamp = new Date().toISOString();

  return Array.from({ length: 6 }, (_, index) => ({
    event_type: 'login_failed',
    source_ip: sourceIp,
    target_user: `demo${index % 2}`,
    service: 'sshd',
    message: `Failed password for invalid user demo${index % 2} from ${sourceIp} port 22 ssh2`,
    severity: 'INFO' as const,
    timestamp,
  }));
}

function healthBadgeVariant(status?: string) {
  switch (status) {
    case 'healthy':
      return 'default';
    case 'degraded':
      return 'secondary';
    default:
      return 'destructive';
  }
}

function formatServiceLabel(name: string) {
  return name.replace(/_/g, ' ');
}

export default function OnboardingPage() {
  const { user } = useAuth();
  const router = useRouter();
  const queryClient = useQueryClient();
  useAlertsWS();

  const [stepIndex, setStepIndex] = useState(0);
  const [copied, setCopied] = useState(false);

  const healthQuery = useQuery({
    queryKey: ['onboarding-health'],
    queryFn: async () => {
      const response = await api.get<SystemHealth>('/health/services');
      return response.data;
    },
    refetchInterval: 10_000,
  });

  const rulesQuery = useQuery({
    queryKey: ['onboarding-rules'],
    queryFn: async () => {
      const response = await api.get<DetectionRule[]>('/rules');
      return response.data;
    },
  });

  const alertsQuery = useQuery({
    queryKey: ['alerts'],
    queryFn: async () => {
      const response = await api.get<Alert[]>('/alerts');
      return response.data;
    },
    refetchInterval: 5_000,
  });

  const replayMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/logs/batch', { logs: buildReplayLogs() });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
      queryClient.invalidateQueries({ queryKey: ['onboarding-health'] });
    },
  });

  const completeMutation = useMutation({
    mutationFn: async () => {
      if (typeof window !== 'undefined') {
        localStorage.setItem('siem_onboarding_complete', 'true');
      }
    },
    onSuccess: () => router.push('/dashboard'),
  });

  useEffect(() => {
    if (user && typeof window !== 'undefined' && localStorage.getItem('siem_onboarding_complete') === 'true') {
      router.push('/dashboard');
    }
  }, [router, user]);

  const services = healthQuery.data?.services || {};
  const serviceEntries = Object.entries(services);
  const allHealthy = healthQuery.data?.status === 'healthy';
  const firstAlertSeen = (alertsQuery.data?.length || 0) > 0;
  const detectionsLoaded = (rulesQuery.data?.length || 0) > 0;
  const canComplete = allHealthy && firstAlertSeen && detectionsLoaded;

  const connectorSnippet = useMemo(() => {
    const baseUrl = (process.env.NEXT_PUBLIC_API_URL || '/api/v1').replace(/\/api\/v1$/, '');
    return JSON.stringify(
      {
        siem_server: baseUrl || 'http://localhost:8080',
        api_key: 'YOUR_EDGE_API_KEY',
        enable_syslog: true,
        syslog_port: 514,
        batch_size: 100,
        flush_interval: 5000000000,
        files: [
          {
            path: '/var/log/auth.log',
            tags: { source: 'linux-auth' },
          },
        ],
      },
      null,
      2
    );
  }, []);

  const onCopy = async () => {
    await navigator.clipboard.writeText(connectorSnippet);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  const currentStep = onboardingSteps[stepIndex];

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(15,23,42,0.08),_transparent_35%),linear-gradient(180deg,_#f8fafc_0%,_#eef2ff_45%,_#ffffff_100%)] text-foreground">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-8 px-4 py-8 md:px-8 lg:px-10">
        <div className="flex flex-col gap-4 rounded-3xl border border-border/60 bg-white/80 p-6 shadow-[0_25px_80px_rgba(15,23,42,0.08)] backdrop-blur">
          <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div className="max-w-3xl">
              <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.22em] text-emerald-700">
                <Rocket className="h-3.5 w-3.5" />
                Time-to-value in 1 hour
              </div>
              <h1 className="text-4xl font-semibold tracking-tight text-slate-950 md:text-5xl">
                Guided SIEM onboarding that gets to first alert fast.
              </h1>
              <p className="mt-3 max-w-3xl text-base text-slate-600 md:text-lg">
                Connect the agent, replay sample events, confirm the bundled detections, and verify the alert pipeline before you hand the workspace to a customer.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button variant="outline" asChild>
                <Link href="/dashboard">Back to dashboard</Link>
              </Button>
              <Button onClick={() => replayMutation.mutate()} disabled={replayMutation.isPending}>
                {replayMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Replay test data
              </Button>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-4">
            {onboardingSteps.map((item, index) => {
              const Icon = item.icon;
              const active = index === stepIndex;
              const completed =
                (index === 0 && Boolean(healthQuery.data?.services?.agent?.status === 'healthy')) ||
                (index === 1 && replayMutation.isSuccess) ||
                (index === 2 && detectionsLoaded) ||
                (index === 3 && firstAlertSeen);

              return (
                <button
                  key={item.title}
                  className={`flex h-full flex-col rounded-2xl border p-4 text-left transition ${active ? 'border-slate-900 bg-slate-950 text-white shadow-lg' : 'border-border bg-white hover:border-slate-300 hover:bg-slate-50'}`}
                  onClick={() => setStepIndex(index)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <Icon className={`h-5 w-5 ${active ? 'text-white' : 'text-slate-500'}`} />
                    {completed ? <CheckCircle2 className={`h-4 w-4 ${active ? 'text-white' : 'text-emerald-600'}`} /> : <Circle className={`h-4 w-4 ${active ? 'text-white/60' : 'text-slate-300'}`} />}
                  </div>
                  <div className="mt-4 text-sm font-semibold uppercase tracking-[0.2em] text-inherit/70">Step {index + 1}</div>
                  <div className="mt-2 text-lg font-semibold">{item.title}</div>
                  <p className={`mt-2 text-sm ${active ? 'text-white/75' : 'text-slate-600'}`}>{item.description}</p>
                </button>
              );
            })}
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-[1.3fr_0.9fr]">
          <div className="space-y-6">
            <Card className="overflow-hidden border-slate-200 shadow-[0_20px_60px_rgba(15,23,42,0.08)]">
              <CardHeader className="border-b bg-slate-950 text-white">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <CardTitle className="text-white">{currentStep.title}</CardTitle>
                    <CardDescription className="text-slate-300">{currentStep.description}</CardDescription>
                  </div>
                  <Badge variant="secondary" className="bg-white/10 text-white">
                    Step {stepIndex + 1}/4
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-5 p-6">
                {stepIndex === 0 ? (
                  <div className="grid gap-5 lg:grid-cols-2">
                    <div className="space-y-4">
                      <div>
                        <p className="text-sm font-medium text-slate-700">Connector config</p>
                        <p className="text-sm text-slate-500">Use this as the starting point for the Go agent on the customer host.</p>
                      </div>
                      <div className="rounded-2xl border border-slate-200 bg-slate-950 p-4 text-sm text-slate-100">
                        <pre className="whitespace-pre-wrap font-mono text-xs leading-6">{connectorSnippet}</pre>
                      </div>
                      <div className="flex flex-wrap gap-3">
                        <Button variant="outline" onClick={onCopy}>
                          <Copy className="mr-2 h-4 w-4" />
                          {copied ? 'Copied' : 'Copy config'}
                        </Button>
                        <Button variant="secondary" onClick={() => setStepIndex(1)}>
                          Next: replay data
                        </Button>
                      </div>
                    </div>

                    <Card className="border-dashed bg-slate-50">
                      <CardHeader>
                        <CardTitle className="text-base">Agent checklist</CardTitle>
                        <CardDescription>Five minutes to a connected source.</CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-3 text-sm text-slate-600">
                        <ChecklistItem done={Boolean(healthQuery.data?.services?.agent?.status === 'healthy')} label="Send one test event from the agent" />
                        <ChecklistItem done={Boolean(healthQuery.data?.services?.kafka?.status === 'healthy')} label="Confirm Kafka metadata is reachable" />
                        <ChecklistItem done={Boolean(healthQuery.data?.services?.indexer?.status === 'healthy')} label="Confirm logs land in Elasticsearch" />
                        <ChecklistItem done={Boolean(healthQuery.data?.services?.alert_pipeline?.status === 'healthy')} label="Confirm an alert can be processed" />
                      </CardContent>
                    </Card>
                  </div>
                ) : null}

                {stepIndex === 1 ? (
                  <div className="grid gap-5 lg:grid-cols-2">
                    <Card className="border-slate-200 bg-slate-50/70">
                      <CardHeader>
                        <CardTitle className="text-base">Replay burst</CardTitle>
                        <CardDescription>Send a six-event failed login burst through the real ingest API.</CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4 text-sm text-slate-600">
                        <p>This validates ingest, Kafka publication, indexer fan-out, and the built-in brute-force detection rule.</p>
                        <div className="flex flex-wrap gap-3">
                          <Button onClick={() => replayMutation.mutate()} disabled={replayMutation.isPending}>
                            {replayMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                            Send replay burst
                          </Button>
                          <Button variant="outline" onClick={() => setStepIndex(2)}>
                            Review detections
                          </Button>
                        </div>
                        {replayMutation.isSuccess ? (
                          <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-emerald-800">
                            Replay accepted. Wait a few seconds for the alert to surface.
                          </div>
                        ) : null}
                      </CardContent>
                    </Card>

                    <Card className="border-slate-200">
                      <CardHeader>
                        <CardTitle className="text-base">CLI fallback</CardTitle>
                        <CardDescription>Use this when you want to exercise the file or CLI path directly.</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="rounded-2xl bg-slate-950 p-4 text-xs text-slate-100">
                          <pre className="whitespace-pre-wrap leading-6">python3 scripts/send_alert.py --url http://localhost:8080 --count 6 --batch</pre>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                ) : null}

                {stepIndex === 2 ? (
                  <div className="space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <h3 className="text-lg font-semibold">Prebuilt detections</h3>
                        <p className="text-sm text-slate-500">These rules should already be present after bootstrapping the backend.</p>
                      </div>
                      <Badge variant={detectionsLoaded ? 'default' : 'destructive'}>{detectionsLoaded ? 'Loaded' : 'Missing'}</Badge>
                    </div>

                    {rulesQuery.isLoading ? (
                      <div className="grid gap-3 md:grid-cols-2">
                        <Skeleton className="h-28 rounded-2xl" />
                        <Skeleton className="h-28 rounded-2xl" />
                      </div>
                    ) : (
                      <div className="grid gap-3 md:grid-cols-2">
                        {rulesQuery.data?.map((rule) => (
                          <div key={rule.id} className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                            <div className="flex items-start justify-between gap-3">
                              <div>
                                <div className="text-base font-semibold">{rule.name}</div>
                                <div className="mt-1 text-sm text-slate-500">{rule.description || 'Prebuilt detection rule'}</div>
                              </div>
                              <Badge variant={rule.is_enabled ? 'default' : 'outline'}>{rule.is_enabled ? 'Enabled' : 'Disabled'}</Badge>
                            </div>
                            <div className="mt-4 flex flex-wrap gap-2 text-xs text-slate-600">
                              <Badge variant="secondary">{rule.rule_type}</Badge>
                              <Badge variant="outline">{rule.severity}</Badge>
                              {rule.threshold ? <Badge variant="outline">threshold {rule.threshold}</Badge> : null}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : null}

                {stepIndex === 3 ? (
                  <div className="grid gap-5 lg:grid-cols-2">
                    <Card className="border-slate-200 bg-slate-50/70">
                      <CardHeader>
                        <CardTitle className="text-base">First alert validation</CardTitle>
                        <CardDescription>This is the customer-facing proof-of-value moment.</CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4 text-sm text-slate-600">
                        <div className="flex items-center gap-3">
                          <Badge variant={firstAlertSeen ? 'default' : 'secondary'}>{firstAlertSeen ? 'Alert observed' : 'Waiting for alert'}</Badge>
                          <span>{alertsQuery.data?.[0]?.rule_name || 'No alert yet'}</span>
                        </div>
                        <div className="flex flex-wrap gap-3">
                          <Button onClick={() => replayMutation.mutate()} disabled={replayMutation.isPending}>
                            {replayMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                            Re-run replay
                          </Button>
                          <Button variant="outline" onClick={() => queryClient.invalidateQueries({ queryKey: ['alerts'] })}>
                            Refresh alerts
                          </Button>
                        </div>
                        <div className={`rounded-xl border p-3 ${canComplete ? 'border-emerald-200 bg-emerald-50 text-emerald-800' : 'border-amber-200 bg-amber-50 text-amber-900'}`}>
                          {canComplete ? 'Everything is ready. You can mark this workspace as onboarded.' : 'Keep replaying until the first alert appears and the pipeline cards are green.'}
                        </div>
                      </CardContent>
                    </Card>

                    <Card className="border-slate-200">
                      <CardHeader>
                        <CardTitle className="text-base">Pipeline readiness</CardTitle>
                        <CardDescription>Auto-checks that update while you work.</CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        {(healthQuery.isLoading ? Array.from({ length: 4 }) : serviceEntries).map((entry, index) => {
                          if (healthQuery.isLoading) {
                            return <Skeleton key={index} className="h-12 rounded-xl" />;
                          }
                          const [name, service] = entry as [string, { status: string; details?: string | null; last_seen_seconds_ago?: number | null }];
                          return (
                            <div key={name} className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-4 py-3">
                              <div>
                                <div className="font-medium capitalize">{formatServiceLabel(name)}</div>
                                <div className="text-xs text-slate-500">{service.details || 'Last heartbeat received'}</div>
                              </div>
                              <Badge variant={healthBadgeVariant(service.status)}>{service.status}</Badge>
                            </div>
                          );
                        })}
                      </CardContent>
                    </Card>
                  </div>
                ) : null}
              </CardContent>
            </Card>

            <div className="grid gap-4 md:grid-cols-3">
              <MiniStat label="Pipeline" value={healthQuery.data?.status || 'loading'} />
              <MiniStat label="Detections" value={String(rulesQuery.data?.length || 0)} />
              <MiniStat label="Alerts" value={String(alertsQuery.data?.length || 0)} />
            </div>
          </div>

          <div className="space-y-6">
            <Card className="border-slate-200 shadow-[0_20px_60px_rgba(15,23,42,0.08)]">
              <CardHeader>
                <CardTitle className="text-base">Under an hour checklist</CardTitle>
                <CardDescription>Keep the customer moving with a narrow, repeatable flow.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 text-sm text-slate-600">
                <ChecklistItem done={Boolean(healthQuery.data?.services?.agent?.status === 'healthy')} label="Agent is shipping at least one event" />
                <ChecklistItem done={Boolean(healthQuery.data?.services?.kafka?.status === 'healthy')} label="Kafka is reachable and ingest is flowing" />
                <ChecklistItem done={Boolean(healthQuery.data?.services?.indexer?.status === 'healthy')} label="Indexing is landing in Elasticsearch" />
                <ChecklistItem done={Boolean(healthQuery.data?.services?.alert_pipeline?.status === 'healthy')} label="Alert pipeline has seen a live event" />
                <ChecklistItem done={detectionsLoaded} label="Built-in detections are loaded" />
                <ChecklistItem done={firstAlertSeen} label="First alert has been validated" />
              </CardContent>
            </Card>

            <Card className="border-slate-200">
              <CardHeader>
                <CardTitle className="text-base">Release gate</CardTitle>
                <CardDescription>Mark the workspace as onboarded once the path is green.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className={`rounded-2xl border p-4 ${canComplete ? 'border-emerald-200 bg-emerald-50' : 'border-slate-200 bg-slate-50'}`}>
                  <div className="flex items-center gap-2 text-sm font-medium">
                    <Activity className="h-4 w-4" />
                    {canComplete ? 'Ready to hand over' : 'Still in progress'}
                  </div>
                  <p className="mt-2 text-sm text-slate-600">
                    Customers convert faster when the first alert appears, the checks are green, and the path to production is obvious.
                  </p>
                </div>
                <Button className="w-full" disabled={!canComplete || completeMutation.isPending} onClick={() => completeMutation.mutate()}>
                  {completeMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  Finish onboarding
                </Button>
                <Button variant="outline" className="w-full" onClick={() => router.push('/dashboard')}>
                  Skip to dashboard
                </Button>
              </CardContent>
            </Card>

            <div className="rounded-2xl border border-dashed border-slate-300 bg-white/80 p-4 text-sm text-slate-600">
              <div className="font-medium text-slate-900">Tip</div>
              <p className="mt-2">
                If the agent is not yet installed, keep the wizard open and replay the batch test first. That validates the alert path while the connector is being configured.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ChecklistItem({ done, label }: { done: boolean; label: string }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-white px-3 py-2">
      {done ? <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-600" /> : <Circle className="mt-0.5 h-4 w-4 text-slate-300" />}
      <span>{label}</span>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <Card className="border-slate-200">
      <CardContent className="p-4">
        <div className="text-xs uppercase tracking-[0.2em] text-slate-500">{label}</div>
        <div className="mt-2 text-xl font-semibold text-slate-950">{value}</div>
      </CardContent>
    </Card>
  );
}