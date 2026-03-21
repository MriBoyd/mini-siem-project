import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Alert } from '@/types';

export default function useAlertsWS() {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const token = localStorage.getItem('access_token');
    if (!token) return;

    const loc = window.location;
    const proto = loc.protocol === 'https:' ? 'wss' : 'ws';
    const base = process.env.NEXT_PUBLIC_API_URL || '/api/v1';

    // Resolve host and path
    let host: string;
    let path: string;
    try {
      if (base.startsWith('http')) {
        const u = new URL(base);
        host = u.host;
        path = u.pathname.replace(/\/$/, '');
      } else {
        host = loc.host;
        path = base.replace(/\/$/, '');
      }
    } catch (e) {
      host = loc.host;
      path = base.replace(/\/$/, '');
    }

    const wsUrl = `${proto}://${host}${path}/ws/alerts?token=${token}`;
    const ws = new WebSocket(wsUrl);

    ws.onmessage = (ev) => {
      try {
        const payload = JSON.parse(ev.data);
        const t = payload.type;
        const data = payload.data;
        if (t === 'alert') {
          const alert: Alert = data;
          queryClient.setQueryData<Alert[]>(['alerts'], (old = []) => {
            const filtered = (old || []).filter((a) => a.id !== alert.id);
            const arr = [alert, ...filtered];
            return arr.slice(0, 50);
          });
          // Update dashboard stats cache incrementally
          queryClient.setQueryData(['dashboard-stats'], (old: any) => {
            if (!old) return old;
            return {
              ...old,
              total_alerts: (old.total_alerts || 0) + 1,
              active_alerts: (old.active_alerts || 0) + 1,
              critical_alerts: (old.critical_alerts || 0) + (alert.severity === 'CRITICAL' ? 1 : 0),
            };
          });
        } else if (t === 'stats') {
          // Replace dashboard stats with authoritative data from server
          queryClient.setQueryData(['dashboard-stats'], () => data);
          // Also trigger a refetch to ensure any server-side derived state is applied
          queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
        }
      } catch (e) {
        // ignore malformed messages
      }
    };

    ws.onopen = () => {
      // Optionally, you could send an initial message
    };

    ws.onclose = () => {
      // reconnect strategy could be added here
    };

    ws.onerror = () => {
      // noop
    };

    return () => {
      ws.close();
    };
  }, [queryClient]);
}
