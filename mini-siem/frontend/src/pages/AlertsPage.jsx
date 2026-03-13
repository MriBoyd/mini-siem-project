import React, { useEffect, useState } from 'react';
import { Typography, Box } from '@mui/material';
import AlertTable from '../components/Alerts/AlertTable';
import { fetchAlerts } from '../services/api';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchAlerts()
      .then((data) => setAlerts(data))
      .catch((err) => {
        console.error(err);
        setError('Unable to load alerts');
      });
  }, []);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Alerts
      </Typography>
      {error ? (
        <Typography color="error">{error}</Typography>
      ) : (
        <AlertTable alerts={alerts} />
      )}
    </Box>
  );
}
