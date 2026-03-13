// simple API wrapper
import axios from 'axios';

export const api = axios.create({
    baseURL: '/api',
    timeout: 5000,
});

export const fetchAlerts = () => api.get('/v1/alerts').then((res) => res.data);
export const fetchDashboardStats = () => api.get('/v1/dashboard/stats').then((res) => res.data);
