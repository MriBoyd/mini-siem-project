import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import { Card, CardHeader, CardContent, Typography, Box, CircularProgress } from '@mui/material';
import { api } from '../../services/api';
import 'leaflet/dist/leaflet.css';

const AttackMap = () => {
    const [attacks, setAttacks] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchAttackData();
        
        // Refresh every 30 seconds
        const interval = setInterval(fetchAttackData, 30000);
        return () => clearInterval(interval);
    }, []);

    const fetchAttackData = async () => {
        try {
            const response = await api.get('/dashboard/attack-map');
            setAttacks(response.data);
            setLoading(false);
        } catch (err) {
            setError('Failed to load attack map data');
            setLoading(false);
        }
    };

    const getMarkerColor = (severity) => {
        switch(severity) {
            case 'CRITICAL': return '#ff0000';
            case 'HIGH': return '#ff6b6b';
            case 'MEDIUM': return '#ffd93d';
            case 'LOW': return '#6bcf7f';
            default: return '#3388ff';
        }
    };

    if (loading) {
        return (
            <Card>
                <CardHeader title="Global Attack Map" />
                <CardContent>
                    <Box display="flex" justifyContent="center" p={3}>
                        <CircularProgress />
                    </Box>
                </CardContent>
            </Card>
        );
    }

    if (error) {
        return (
            <Card>
                <CardHeader title="Global Attack Map" />
                <CardContent>
                    <Typography color="error">{error}</Typography>
                </CardContent>
            </Card>
        );
    }

    return (
        <Card>
            <CardHeader 
                title="Global Attack Map" 
                subheader="Real-time attack sources by geolocation"
            />
            <CardContent>
                <Box height={400} width="100%">
                    <MapContainer
                        center={[20, 0]}
                        zoom={2}
                        style={{ height: '100%', width: '100%' }}
                    >
                        <TileLayer
                            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                            attribution='&copy; <a href="http://osm.org/copyright">OpenStreetMap</a>'
                        />
                        {attacks.map((attack, index) => (
                            <CircleMarker
                                key={index}
                                center={[attack.latitude, attack.longitude]}
                                radius={Math.min(attack.count / 10, 30)}
                                fillColor={getMarkerColor(attack.severity)}
                                color="#000"
                                weight={1}
                                opacity={1}
                                fillOpacity={0.8}
                            >
                                <Popup>
                                    <Typography variant="subtitle2">{attack.country}</Typography>
                                    <Typography variant="body2">
                                        Attacks: {attack.count}<br/>
                                        Severity: {attack.severity}<br/>
                                        Top IP: {attack.top_ip}
                                    </Typography>
                                </Popup>
                            </CircleMarker>
                        ))}
                    </MapContainer>
                </Box>
            </CardContent>
        </Card>
    );
};

export default AttackMap;