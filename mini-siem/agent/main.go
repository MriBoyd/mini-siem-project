package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"agent-go/collector"
	"agent-go/config"
	"agent-go/queue"
	"agent-go/shipper"
)

func main() {
	// Load configuration
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create message queue (buffered channel)
	logQueue := queue.New(10000)

	// Create wait group for all goroutines
	var wg sync.WaitGroup

	// Start file collectors
	for _, fileConfig := range cfg.Files {
		fileCollector := collector.NewFileCollector(
			fileConfig.Path,
			fileConfig.Tags,
			logQueue,
			cfg,
		)

		wg.Add(1)
		go func(c *collector.FileCollector) {
			defer wg.Done()
			if err := c.Start(ctx); err != nil {
				log.Printf("File collector error: %v", err)
			}
		}(fileCollector)

		log.Printf("Started file collector for: %s", fileConfig.Path)
	}

	// Start syslog collector if enabled
	if cfg.EnableSyslog {
		syslogCollector := collector.NewSyslogCollector(
			cfg.SyslogPort,
			logQueue,
			cfg,
		)

		wg.Add(1)
		go func(c *collector.SyslogCollector) {
			defer wg.Done()
			if err := c.Start(ctx); err != nil {
				log.Printf("Syslog collector error: %v", err)
			}
		}(syslogCollector)

		log.Printf("Started syslog collector on port: %d", cfg.SyslogPort)
	}

	// Start shipper
	logShipper := shipper.New(logQueue, cfg)

	wg.Add(1)
	go func(s *shipper.Shipper) {
		defer wg.Done()
		if err := s.Start(ctx); err != nil {
			log.Printf("Shipper error: %v", err)
		}
	}(logShipper)

	// Status reporter
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := logShipper.GetStats()
				log.Printf("Status - Sent: %d, Failed: %d, Queue: %d, Uptime: %s",
					stats.SentCount,
					stats.FailedCount,
					logQueue.Size(),
					time.Since(stats.StartTime).Round(time.Second),
				)
			}
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutting down...")
	cancel()

	// Wait for all goroutines to finish
	wg.Wait()
	log.Println("Agent stopped")
}
