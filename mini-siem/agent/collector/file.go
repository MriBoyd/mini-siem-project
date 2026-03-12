package collector

import (
    "bufio"
    "context"
    "fmt"
    "os"
    "path/filepath"
    "time"

    "github.com/fsnotify/fsnotify"
    
    "agent-go/config"
    "agent-go/models"
    "agent-go/queue"
)

// FileCollector monitors and reads log files
type FileCollector struct {
    path    string
    tags    map[string]string
    queue   *queue.Queue
    cfg     *config.Config
    offset  int64
}

// NewFileCollector creates a new file collector
func NewFileCollector(path string, tags map[string]string, q *queue.Queue, cfg *config.Config) *FileCollector {
    return &FileCollector{
        path:   path,
        tags:   tags,
        queue:  q,
        cfg:    cfg,
        offset: 0,
    }
}

// Start begins monitoring the file
func (fc *FileCollector) Start(ctx context.Context) error {
    // Initialize offset to end of file
    if info, err := os.Stat(fc.path); err == nil {
        fc.offset = info.Size()
    }
    
    // Create watcher
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return fmt.Errorf("failed to create watcher: %w", err)
    }
    defer watcher.Close()
    
    // Watch the directory containing the file
    dir := filepath.Dir(fc.path)
    if err := watcher.Add(dir); err != nil {
        return fmt.Errorf("failed to watch directory: %w", err)
    }
    
    for {
        select {
        case <-ctx.Done():
            return nil
            
        case event, ok := <-watcher.Events:
            if !ok {
                return nil
            }
            
            // Check if our file was modified
            if event.Name == fc.path && event.Op&fsnotify.Write == fsnotify.Write {
                if err := fc.readNewLines(); err != nil {
                    // Log error but continue
                    fmt.Printf("Error reading file: %v\n", err)
                }
            }
            
        case err, ok := <-watcher.Errors:
            if !ok {
                return nil
            }
            fmt.Printf("Watcher error: %v\n", err)
        }
    }
}

// readNewLines reads new lines appended to the file
func (fc *FileCollector) readNewLines() error {
    file, err := os.Open(fc.path)
    if err != nil {
        return err
    }
    defer file.Close()
    
    // Seek to last read position
    if _, err := file.Seek(fc.offset, 0); err != nil {
        return err
    }
    
    // Read new lines
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        if line == "" {
            continue
        }
        
        log := models.NewFileLog(fc.path, line, fc.tags)
        fc.queue.Push(log)
    }
    
    // Update offset to current end
    if newOffset, err := file.Seek(0, 1); err == nil {
        fc.offset = newOffset
    }
    
    return scanner.Err()
}