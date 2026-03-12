package config

import (
    "encoding/json"
    "os"
    "time"
)

// FileConfig represents a file to monitor
type FileConfig struct {
    Path string            `json:"path"`
    Tags map[string]string `json:"tags"`
}

// Config represents agent configuration
type Config struct {
    SiemServer    string        `json:"siem_server"`
    APIKey        string        `json:"api_key"`
    EnableSyslog  bool          `json:"enable_syslog"`
    SyslogPort    int           `json:"syslog_port"`
    BatchSize     int           `json:"batch_size"`
    FlushInterval time.Duration `json:"flush_interval"`
    Files         []FileConfig  `json:"files"`
    
    // Derived fields
    BatchInterval time.Duration
}

// Load reads and parses the config file
func Load(path string) (*Config, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var cfg Config
    if err := json.NewDecoder(file).Decode(&cfg); err != nil {
        return nil, err
    }

    // Set defaults
    if cfg.BatchSize == 0 {
        cfg.BatchSize = 100
    }
    if cfg.FlushInterval == 0 {
        cfg.FlushInterval = 5 * time.Second
    }
    if cfg.SyslogPort == 0 {
        cfg.SyslogPort = 514
    }

    return &cfg, nil
}