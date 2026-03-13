import React from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Typography,
} from '@mui/material';

export default function AlertTable({ alerts = [] }) {
  if (!alerts.length) {
    return <Typography>No alerts found.</Typography>;
  }

  return (
    <TableContainer component={Paper}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>First Seen</TableCell>
            <TableCell>Severity</TableCell>
            <TableCell>Rule</TableCell>
            <TableCell>Description</TableCell>
            <TableCell>Source</TableCell>
            <TableCell>Status</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {alerts.map((alert) => (
            <TableRow key={alert.id} hover>
              <TableCell>{new Date(alert.first_seen).toLocaleString()}</TableCell>
              <TableCell>{alert.severity}</TableCell>
              <TableCell>{alert.rule_name}</TableCell>
              <TableCell>{alert.description}</TableCell>
              <TableCell>{alert.source_ip}</TableCell>
              <TableCell>{alert.status}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
