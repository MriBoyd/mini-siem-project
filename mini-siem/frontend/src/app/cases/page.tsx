'use client';

import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { AlertTriangle, ArrowRight, CheckCircle2, Clock3, Gauge, ListTodo, Loader2, PlayCircle, UserCog } from 'lucide-react';

import api from '@/lib/api';
import { useAuth } from '@/hooks/use-auth';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { CaseDetail, CasePlaybook, CaseRecord, CaseStatus } from '@/types';

const STATUS_OPTIONS: CaseStatus[] = ['NEW', 'INVESTIGATING', 'AWAITINGCUSTOMER', 'MITIGATED', 'RESOLVED', 'FALSEPOSITIVE', 'ESCALATED', 'CLOSED'];

function formatRelative(dateValue?: string | null) {
  if (!dateValue) return 'n/a';
  const value = new Date(dateValue).getTime() - Date.now();
  const minutes = Math.round(Math.abs(value) / 60000);
  return value >= 0 ? `in ${minutes}m` : `${minutes}m ago`;
}

export default function CasesPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [statusValue, setStatusValue] = useState<CaseStatus>('NEW');
  const [ownerEmail, setOwnerEmail] = useState('');
  const [ownerUserId, setOwnerUserId] = useState('');
  const [outcome, setOutcome] = useState('');
  const [postmortemSummary, setPostmortemSummary] = useState('');
  const [timelineMessage, setTimelineMessage] = useState('');

  const casesQuery = useQuery({
    queryKey: ['cases'],
    queryFn: async () => (await api.get<CaseRecord[]>('/cases')).data,
    refetchInterval: 10_000,
  });

  const playbooksQuery = useQuery({
    queryKey: ['case-playbooks'],
    queryFn: async () => (await api.get<CasePlaybook[]>('/case-playbooks')).data,
  });

  const selectedCaseQuery = useQuery({
    queryKey: ['case', selectedCaseId],
    enabled: Boolean(selectedCaseId),
    queryFn: async () => (await api.get<CaseDetail>(`/cases/${selectedCaseId}`)).data,
    refetchInterval: 5_000,
  });

  useEffect(() => {
    if (!selectedCaseId && casesQuery.data?.length) {
      setSelectedCaseId(casesQuery.data[0].id);
    }
  }, [casesQuery.data, selectedCaseId]);

  useEffect(() => {
    const record = selectedCaseQuery.data?.case_record;
    if (record) {
      setStatusValue(record.status);
      setOwnerEmail(record.owner_email || '');
      setOwnerUserId(record.owner_user_id || '');
      setOutcome(record.outcome || '');
      setPostmortemSummary(record.postmortem_summary || '');
    }
  }, [selectedCaseQuery.data]);

  const selectedPlaybook = useMemo(() => selectedCaseQuery.data?.playbook, [selectedCaseQuery.data]);

  const updateCaseMutation = useMutation({
    mutationFn: async () => {
      await api.patch(`/cases/${selectedCaseId}`, {
        status: statusValue,
        owner_email: ownerEmail || null,
        owner_user_id: ownerUserId || null,
        outcome: outcome || null,
        postmortem_summary: postmortemSummary || null,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      queryClient.invalidateQueries({ queryKey: ['case', selectedCaseId] });
    },
  });

  const addEventMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/cases/${selectedCaseId}/timeline`, {
        event_type: 'postmortem.note',
        message: timelineMessage,
        metadata: { source: 'cases-page' },
      });
    },
    onSuccess: () => {
      setTimelineMessage('');
      queryClient.invalidateQueries({ queryKey: ['case', selectedCaseId] });
    },
  });

  const runPlaybookMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/cases/${selectedCaseId}/playbook/run`, {});
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      queryClient.invalidateQueries({ queryKey: ['case', selectedCaseId] });
    },
  });

  const cases = casesQuery.data || [];
  const currentCase = selectedCaseQuery.data?.case_record;
  const openCases = cases.filter((item) => !['RESOLVED', 'FALSEPOSITIVE', 'CLOSED'].includes(item.status));
  const breached = cases.filter((item) => item.status === 'ESCALATED').length;

  return (
    <div className="min-h-screen bg-[linear-gradient(180deg,_#f8fafc_0%,_#eef2ff_45%,_#ffffff_100%)] p-6 text-slate-950 md:p-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <div className="flex flex-col gap-4 rounded-3xl border border-slate-200 bg-white/80 p-6 shadow-[0_20px_60px_rgba(15,23,42,0.08)] backdrop-blur md:flex-row md:items-start md:justify-between">
          <div className="max-w-3xl">
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-amber-700">
              <Gauge className="h-3.5 w-3.5" />
              Case management
            </div>
            <h1 className="text-4xl font-semibold tracking-tight">Alert to outcome in one workflow.</h1>
            <p className="mt-3 text-base text-slate-600">
              Track ownership, SLA timers, playbooks, responder actions, and the postmortem timeline in one place so the team can focus on MTTR instead of alert volume.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="outline" asChild>
              <Link href="/dashboard">Back to dashboard</Link>
            </Button>
            <Button variant="outline" asChild>
              <Link href="/onboarding">Onboarding</Link>
            </Button>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <MetricCard label="Open cases" value={String(openCases.length)} icon={<ListTodo className="h-4 w-4" />} />
          <MetricCard label="Escalated" value={String(breached)} icon={<AlertTriangle className="h-4 w-4" />} />
          <MetricCard label="Playbooks" value={String(playbooksQuery.data?.length || 0)} icon={<PlayCircle className="h-4 w-4" />} />
        </div>

        <div className="grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
          <Card className="border-slate-200 shadow-[0_20px_60px_rgba(15,23,42,0.08)]">
            <CardHeader>
              <CardTitle>Cases</CardTitle>
              <CardDescription>Active incidents and their SLA state.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {casesQuery.isLoading ? (
                <div className="space-y-2 text-sm text-slate-500">
                  Loading cases...
                </div>
              ) : (
                cases.map((incident) => {
                  const selected = incident.id === selectedCaseId;
                  return (
                    <button
                      key={incident.id}
                      onClick={() => setSelectedCaseId(incident.id)}
                      className={`w-full rounded-2xl border p-4 text-left transition ${selected ? 'border-slate-950 bg-slate-950 text-white shadow-lg' : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50'}`}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-sm uppercase tracking-[0.2em] text-inherit/60">{incident.severity}</span>
                            <Badge variant={incident.status === 'ESCALATED' ? 'destructive' : selected ? 'secondary' : 'outline'}>{incident.status}</Badge>
                          </div>
                          <div className="mt-2 text-lg font-semibold">{incident.title}</div>
                          <div className={`mt-1 text-sm ${selected ? 'text-white/75' : 'text-slate-600'}`}>{incident.summary}</div>
                        </div>
                        <ArrowRight className={`mt-1 h-4 w-4 ${selected ? 'text-white' : 'text-slate-400'}`} />
                      </div>
                      <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
                        <Badge variant={selected ? 'secondary' : 'outline'}>Owner: {incident.owner_email || incident.owner_user_id || 'unassigned'}</Badge>
                        <Badge variant={selected ? 'secondary' : 'outline'}>SLA {formatRelative(incident.sla_due_at)}</Badge>
                        <Badge variant={selected ? 'secondary' : 'outline'}>Escalation {formatRelative(incident.escalation_at)}</Badge>
                      </div>
                    </button>
                  );
                })
              )}
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-[0_20px_60px_rgba(15,23,42,0.08)]">
            <CardHeader>
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <CardTitle>{currentCase?.title || 'Select a case'}</CardTitle>
                  <CardDescription>{currentCase?.summary || 'Case detail appears here'}</CardDescription>
                </div>
                {currentCase ? (
                  <div className="flex items-center gap-2">
                    <Badge>{currentCase.status}</Badge>
                    <Badge variant={currentCase.escalated_at ? 'destructive' : 'secondary'}>{currentCase.escalated_at ? 'Escalated' : 'SLA tracking'}</Badge>
                  </div>
                ) : null}
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              {currentCase ? (
                <>
                  <div className="grid gap-4 md:grid-cols-3">
                    <FieldCard label="Owner" value={currentCase.owner_email || currentCase.owner_user_id || 'Unassigned'} icon={<UserCog className="h-4 w-4" />} />
                    <FieldCard label="Primary alert" value={currentCase.primary_alert_id} icon={<CheckCircle2 className="h-4 w-4" />} />
                    <FieldCard label="SLA due" value={currentCase.sla_due_at ? new Date(currentCase.sla_due_at).toLocaleString() : 'n/a'} icon={<Clock3 className="h-4 w-4" />} />
                  </div>

                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label>Status</Label>
                      <Select value={statusValue} onValueChange={(value) => setStatusValue(value as CaseStatus)}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select status" />
                        </SelectTrigger>
                        <SelectContent>
                          {STATUS_OPTIONS.map((status) => (
                            <SelectItem key={status} value={status}>{status}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Owner email</Label>
                      <Input value={ownerEmail} onChange={(event) => setOwnerEmail(event.target.value)} placeholder="responder@example.com" />
                    </div>
                    <div className="space-y-2">
                      <Label>Owner user id</Label>
                      <Input value={ownerUserId} onChange={(event) => setOwnerUserId(event.target.value)} placeholder="optional user id" />
                    </div>
                    <div className="space-y-2">
                      <Label>Outcome</Label>
                      <Input value={outcome} onChange={(event) => setOutcome(event.target.value)} placeholder="contained, false positive, customer confirmed" />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Postmortem summary</Label>
                    <textarea
                      rows={4}
                      value={postmortemSummary}
                      onChange={(event) => setPostmortemSummary(event.target.value)}
                      placeholder="What happened, why, and what changed afterward"
                      className="min-h-24 w-full rounded-lg border border-input bg-transparent px-2.5 py-2 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                    />
                  </div>

                  <div className="flex flex-wrap gap-3">
                    <Button onClick={() => updateCaseMutation.mutate()} disabled={updateCaseMutation.isPending || !selectedCaseId}>
                      {updateCaseMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                      Save case
                    </Button>
                    <Button variant="outline" onClick={() => runPlaybookMutation.mutate()} disabled={runPlaybookMutation.isPending || !selectedCaseId}>
                      {runPlaybookMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <PlayCircle className="mr-2 h-4 w-4" />}
                      Run playbook
                    </Button>
                  </div>

                  <div className="space-y-2">
                    <Label>Timeline note</Label>
                    <textarea
                      rows={3}
                      value={timelineMessage}
                      onChange={(event) => setTimelineMessage(event.target.value)}
                      placeholder="Add an investigation note, containment update, or postmortem observation"
                      className="min-h-20 w-full rounded-lg border border-input bg-transparent px-2.5 py-2 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                    />
                    <div className="flex justify-end">
                      <Button variant="secondary" onClick={() => addEventMutation.mutate()} disabled={addEventMutation.isPending || !timelineMessage.trim()}>
                        {addEventMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                        Add timeline event
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-semibold">Playbook</div>
                        <div className="text-sm text-slate-600">{selectedPlaybook?.name || 'No playbook attached'}</div>
                      </div>
                      {selectedPlaybook ? <Badge variant="outline">{selectedPlaybook.sla_minutes}m SLA</Badge> : null}
                    </div>
                    {selectedPlaybook?.steps?.length ? (
                      <div className="space-y-2">
                        {selectedPlaybook.steps.map((step, index) => (
                          <div key={`${selectedPlaybook.id}-${index}`} className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm">
                            <div className="font-medium">{String(step.title || `Step ${index + 1}`)}</div>
                            <div className="text-slate-600">{String(step.description || step.action_type || 'playbook step')}</div>
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </div>

                  <div className="space-y-3">
                    <div className="text-sm font-semibold uppercase tracking-[0.2em] text-slate-500">Timeline</div>
                    <div className="space-y-3">
                      {selectedCaseQuery.data?.timeline.map((event) => (
                        <div key={event.id} className="rounded-2xl border border-slate-200 bg-white p-4">
                          <div className="flex items-center justify-between gap-3">
                            <div className="font-medium">{event.event_type}</div>
                            <div className="text-xs text-slate-500">{new Date(event.created_at).toLocaleString()}</div>
                          </div>
                          <div className="mt-1 text-sm text-slate-600">{event.message}</div>
                          {event.actor_email ? <div className="mt-2 text-xs text-slate-500">by {event.actor_email}</div> : null}
                        </div>
                      ))}
                      {!selectedCaseQuery.data?.timeline.length ? <div className="text-sm text-slate-500">No timeline events yet.</div> : null}
                    </div>
                  </div>
                </>
              ) : (
                <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-600">
                  Select a case from the list to inspect the outcome chain.
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, icon }: { label: string; value: string; icon: ReactNode }) {
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

function FieldCard({ label, value, icon }: { label: string; value: string; icon: ReactNode }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-center justify-between gap-2 text-xs uppercase tracking-[0.2em] text-slate-500">
        <span>{label}</span>
        {icon}
      </div>
      <div className="mt-2 break-all text-sm font-medium text-slate-950">{value}</div>
    </div>
  );
}