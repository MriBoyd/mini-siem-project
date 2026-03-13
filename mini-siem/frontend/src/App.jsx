import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { AppBar, Toolbar, Typography, Button, Container } from '@mui/material';

import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';

function App() {
    return (
        <Router>
            <AppBar position="static">
                <Toolbar>
                    <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                        Mini SIEM
                    </Typography>
                    <Button color="inherit" component={Link} to="/">
                        Dashboard
                    </Button>
                    <Button color="inherit" component={Link} to="/alerts">
                        Alerts
                    </Button>
                </Toolbar>
            </AppBar>
            <Container sx={{ mt: 2 }}>
                <Routes>
                    <Route path="/" element={<DashboardPage />} />
                    <Route path="/alerts" element={<AlertsPage />} />
                </Routes>
            </Container>
        </Router>
    );
}

export default App;
