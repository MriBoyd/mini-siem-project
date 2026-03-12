package collector

import (
    "context"
    "fmt"
    "net"
    "strings"
    "time"

    "agent-go/config"
    "agent-go/models"
    "agent-go/queue"
)

// SyslogCollector listens for UDP syslog messages
type SyslogCollector struct {
    port    int
    queue   *queue.Queue
    cfg     *config.Config
    conn    *net.UDPConn
}

// NewSyslogCollector creates a new syslog collector
func NewSyslogCollector(port int, q *queue.Queue, cfg *config.Config) *SyslogCollector {
    return &SyslogCollector{
        port:  port,
        queue: q,
        cfg:   cfg,
    }
}

// Start begins listening for syslog messages
func (sc *SyslogCollector) Start(ctx context.Context) error {
    addr := &net.UDPAddr{
        Port: sc.port,
        IP:   net.ParseIP("0.0.0.0"),
    }
    
    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        return fmt.Errorf("failed to listen on UDP port %d: %w", sc.port, err)
    }
    defer conn.Close()
    
    sc.conn = conn
    
    // Set read buffer size (increase for high load)
    if err := conn.SetReadBuffer(65535); err != nil {
        fmt.Printf("Warning: failed to set read buffer: %v\n", err)
    }
    
    buffer := make([]byte, 65535)
    
    for {
        select {
        case <-ctx.Done():
            return nil
            
        default:
            // Set read deadline for graceful shutdown
            if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
                continue
            }
            
            n, addr, err := conn.ReadFromUDP(buffer)
            if err != nil {
                if !strings.Contains(err.Error(), "timeout") {
                    fmt.Printf("Error reading UDP: %v\n", err)
                }
                continue
            }
            
            // Create log entry
            log := models.NewSyslogLog(
                addr.IP.String(),
                string(buffer[:n]),
            )
            
            // Non-blocking push to queue
            sc.queue.Push(log)
        }
    }
}