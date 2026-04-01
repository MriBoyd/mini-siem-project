package queue

import (
	"sync"

	"agent-go/models"
)

// Queue is a thread-safe log queue
type Queue struct {
	items   []*models.Log
	mu      sync.RWMutex
	cond    *sync.Cond
	maxSize int
}

// New creates a new queue
func New(maxSize int) *Queue {
	q := &Queue{
		items:   make([]*models.Log, 0),
		maxSize: maxSize,
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// Push adds a log to the queue (blocks if full)
func (q *Queue) Push(log *models.Log) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Wait if queue is full
	for len(q.items) >= q.maxSize {
		q.cond.Wait()
	}

	q.items = append(q.items, log)
	q.cond.Signal() // Signal waiting consumers
}

// TryPush adds a log to the queue without blocking.
// Returns false when the queue is full.
func (q *Queue) TryPush(log *models.Log) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) >= q.maxSize {
		return false
	}

	q.items = append(q.items, log)
	q.cond.Signal()
	return true
}

// Pop removes and returns a log from the queue
// Returns nil if queue is empty and block=false
func (q *Queue) Pop(block bool) *models.Log {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Wait if queue is empty and block=true
	for block && len(q.items) == 0 {
		q.cond.Wait()
	}

	if len(q.items) == 0 {
		return nil
	}

	item := q.items[0]
	q.items = q.items[1:]
	q.cond.Signal() // Signal waiting producers

	return item
}

// PopBatch retrieves up to max items from queue
func (q *Queue) PopBatch(max int, block bool) []*models.Log {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Wait if queue is empty and block=true
	for block && len(q.items) == 0 {
		q.cond.Wait()
	}

	if len(q.items) == 0 {
		return nil
	}

	batchSize := max
	if batchSize > len(q.items) {
		batchSize = len(q.items)
	}

	batch := make([]*models.Log, batchSize)
	copy(batch, q.items[:batchSize])
	q.items = q.items[batchSize:]

	q.cond.Signal() // Signal waiting producers

	return batch
}

// Size returns current queue size
func (q *Queue) Size() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.items)
}
