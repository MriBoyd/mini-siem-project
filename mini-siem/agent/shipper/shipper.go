package shipper

import (
    "bytes"
    "context"
    "fmt"
    "net/http"
    "sync"
    "sync/atomic"
    "time"

    "agent-go/config"
    "agent-go/models"
    "agent-go/queue"
)

// Shipper sends logs to the SIEM server
type Shipper struct {
    queue       *queue.Queue
    cfg         *config.Config
    client      *http.Client
    sentCount   uint64
    failedCount uint64
    startTime   time.Time
    mu          sync.RWMutex
}

// Stats represents shipper statistics
type Stats struct {
    SentCount   uint64
    FailedCount uint64
    StartTime   time.Time
}

// New creates a new shipper
func New(q *queue.Queue, cfg *config.Config) *Shipper {
    return &Shipper{
        queue:     q,
        cfg:       cfg,
        client: &http.Client{
            Timeout: 5 * time.Second,
            Transport: &http.Transport{
                MaxIdleConns:        10,
                MaxIdleConnsPerHost: 5,
                IdleConnTimeout:     30 * time.Second,
            },
        },
        startTime: time.Now(),
    }
}

// Start begins the shipping process
func (s *Shipper) Start(ctx context.Context) error {
    ticker := time.NewTicker(s.cfg.FlushInterval)
    defer ticker.Stop()
    
    var batch []*models.Log
    
    for {
        select {
        case <-ctx.Done():
            // Send remaining logs before exit
            if len(batch) > 0 {
                s.sendBatch(batch)
            }
            return nil
            
        case <-ticker.C:
            if len(batch) > 0 {
                s.sendBatch(batch)
                batch = nil
            }
            
        default:
            // Try to get a log from queue
            log := s.queue.Pop(false) // Non-blocking
            if log == nil {
                // No logs available, wait a bit
                time.Sleep(100 * time.Millisecond)
                continue
            }
            
            batch = append(batch, log)
            
            // Send if batch is full
            if len(batch) >= s.cfg.BatchSize {
                s.sendBatch(batch)
                batch = nil
            }
        }
    }
}

// sendBatch sends a batch of logs to the SIEM server
func (s *Shipper) sendBatch(batch []*models.Log) {
    // Create batch request
    batchReq := &models.Batch{Logs: batch}
    data, err := batchReq.ToJSON()
    if err != nil {
        s.incrementFailed(uint64(len(batch)))
        fmt.Printf("Failed to marshal batch: %v\n", err)
        return
    }
    
    // Create request
    url := fmt.Sprintf("%s/api/v1/logs/batch", s.cfg.SiemServer)
    req, err := http.NewRequest("POST", url, bytes.NewReader(data))
    if err != nil {
        s.incrementFailed(uint64(len(batch)))
        fmt.Printf("Failed to create request: %v\n", err)
        return
    }
    
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-API-Key", s.cfg.APIKey)
    
    // Send request
    resp, err := s.client.Do(req)
    if err != nil {
        s.incrementFailed(uint64(len(batch)))
        fmt.Printf("Failed to send batch: %v\n", err)
        s.retryBatch(batch) // Re-queue for retry
        return
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == http.StatusAccepted {
        atomic.AddUint64(&s.sentCount, uint64(len(batch)))
    } else {
        s.incrementFailed(uint64(len(batch)))
        fmt.Printf("Server returned %d for batch\n", resp.StatusCode)
        s.retryBatch(batch) // Re-queue for retry
    }
}

// retryBatch puts logs back in queue for retry
func (s *Shipper) retryBatch(batch []*models.Log) {
    for _, log := range batch {
        // Non-blocking push, but might block if queue is full
        s.queue.Push(log)
    }
}

// incrementFailed adds to failed count
func (s *Shipper) incrementFailed(count uint64) {
    atomic.AddUint64(&s.failedCount, count)
}

// GetStats returns current statistics
func (s *Shipper) GetStats() Stats {
    return Stats{
        SentCount:   atomic.LoadUint64(&s.sentCount),
        FailedCount: atomic.LoadUint64(&s.failedCount),
        StartTime:   s.startTime,
    }
}