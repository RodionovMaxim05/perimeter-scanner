package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"perimeter-scanner/infrastructure/logger"
	"perimeter-scanner/internal/adapter/masscan"
	"perimeter-scanner/internal/adapter/nmap"
	"perimeter-scanner/internal/adapter/postgres"
	"perimeter-scanner/internal/adapter/telegram"
	"perimeter-scanner/internal/adapter/vulners"
	"perimeter-scanner/internal/config"
	"perimeter-scanner/internal/usecase"
)

func run(ctx context.Context) error {
	// config
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "server configuration file")
	flag.Parse()

	cfg := config.MustLoad(configPath)

	// logger
	log := logger.MustMakeLogger(cfg.Logger.LogLevel)
	log.Info("starting application...")
	log.Debug("debug messages are enabled")

	// Adapters

	masscanScanner := masscan.NewScannerAdapter(cfg.Scanner.BinaryPath, cfg.Scanner.Rate, cfg.Scanner.Interface, log)
	nmapEnricher := nmap.NewEnricherAdapter(log)
	var vulnersClient usecase.ExploitChecker
	if cfg.Vulners.APIKey != "" {
		vulnersClient = vulners.NewExploitCheckerAdapter(cfg.Vulners.APIKey)
	} else {
		log.Info("Vulners API key not set, exploit detection disabled")
		vulnersClient = &vulners.NoopExploitChecker{}
	}
	telegramNotifier := telegram.NewNotifierAdapter(cfg.Telegram.Token, cfg.Telegram.ChatID)

	// repo database
	pool, err := pgxpool.New(ctx, cfg.Database.URL())
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		log.Info("Closing database connection pool...")
		pool.Close()
	}()

	postgresClient, err := postgres.NewDBRepository(ctx, pool)
	if err != nil {
		return fmt.Errorf("failed to create db adapter: %w", err)
	}

	// Usercases

	perimeterScanner := usecase.NewScannerUseCase(
		masscanScanner,
		nmapEnricher,
		vulnersClient,
		postgresClient,
		telegramNotifier,
		cfg.Application.NotificationStrategy,
		cfg.Application.WorkerCount,
		log,
	)

	log.Info("Perimeter scanner architecture initialized successfully. Launching daemon...")

	scanChan := make(chan time.Time, 1)
	scanChan <- time.Now()

	scanInterval := time.Duration(cfg.Application.ScanInterval) * time.Minute
	go func() {
		ticker := time.NewTicker(scanInterval)
		defer ticker.Stop()
		for t := range ticker.C {
			select {
			case scanChan <- t:
			default:
			}
		}
	}()

	log.Info("Scanner daemon is running", "interval", scanInterval.String())

	for {
		select {
		case <-ctx.Done():
			log.Info("Received shutdown signal. Stopping scanner daemon...")
			return nil

		case <-scanChan:
			log.Info("Launching perimeter scan...")
			if err := perimeterScanner.Execute(ctx, cfg.Scanner.Targets, cfg.Scanner.Ports); err != nil {
				log.Error("Scan execution failed", "error", err)
			} else {
				log.Info("Scan session completed successfully.")
			}
		}
	}
}

func main() {
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	if err := run(ctx); err != nil {
		_, err = fmt.Fprintln(os.Stderr, err)
		if err != nil {
			fmt.Printf("launching server error: %s\n", err)
		}
		cancel()
		os.Exit(1)
	}
}
