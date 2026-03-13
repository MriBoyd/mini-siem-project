import React, { useEffect, useState } from 'react';
import { Card, CardContent, Grid, Typography } from '@mui/material';
import { fetchDashboardStats } from '../services/api';

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDashboardStats()
      .then((data) => setStats(data))
      .catch((err) => {
        console.error(err);
        setError('Unable to load dashboard stats');
      });
  }, []);

  if (error) {
    return <Typography color="error">{error}</Typography>;
  }

  if (!stats) {
    return <Typography>Loading dashboard…</Typography>;
  }

  return (
    <Grid container spacing={2}>
      <Grid item xs={12} md={3}>
        <Card>
          <CardContent>
            <Typography variant="subtitle2" color="textSecondary" gutterBottom>
              Total logs
            </Typography>
            <Typography variant="h4">{stats.total_logs}</Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={3}>
        <Card>
          <CardContent>
            <Typography variant="subtitle2" color="textSecondary" gutterBottom>
              Total alerts
            </Typography>
            <Typography variant="h4">{stats.total_alerts}</Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={3}>
        <Card>
          <CardContent>
            <Typography variant="subtitle2" color="textSecondary" gutterBottom>
              Active alerts
            </Typography>
            <Typography variant="h4">{stats.active_alerts}</Typography>
          </CardContent>
        </Card>
      </Grid>

      <Grid item xs={12} md={3}>
        <Card>
          <CardContent>
            <Typography variant="subtitle2" color="textSecondary" gutterBottom>
              Critical alerts
            </Typography>
            <Typography variant="h4">{stats.critical_alerts}</Typography>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );
}
