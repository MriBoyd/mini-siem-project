// WebSocket client for realtime updates

export function connect(url) {
    return new WebSocket(url);
}
