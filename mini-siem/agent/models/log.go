package models

import (
    "encoding/json"
    "time"
)

// Log represents a structured log entry
type Log struct {
    Timestamp  string            `json:"timestamp"`
    Source     string            `json:"source"`
    Host       string            `json:"host,omitempty"`
    File       string            `json:"file,omitempty"`
    Message    string            `json:"message"`
    SourceType string            `json:"source_type"`
    Tags       map[string]string `json:"tags,omitempty"`
}

// NewFileLog creates a log from a file
func NewFileLog(filePath, message string, tags map[string]string) *Log {
    return &Log{
        Timestamp:  time.Now().UTC().Format(time.RFC3339),
        Source:     "file",
        File:       filePath,
        Message:    message,
        SourceType: "file",
        Tags:       tags,
    }
}

// NewSyslogLog creates a log from syslog
func NewSyslogLog(host, message string) *Log {
    return &Log{
        Timestamp:  time.Now().UTC().Format(time.RFC3339),
        Source:     "syslog",
        Host:       host,
        Message:    message,
        SourceType: "syslog",
    }
}

// ToJSON serializes the log to JSON
func (l *Log) ToJSON() ([]byte, error) {
    return json.Marshal(l)
}

// Batch represents a batch of logs for shipping
type Batch struct {
    Logs []*Log `json:"logs"`
}

// ToJSON serializes the batch to JSON
func (b *Batch) ToJSON() ([]byte, error) {
    return json.Marshal(b)
}