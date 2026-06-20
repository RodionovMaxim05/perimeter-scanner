package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/jackc/pgx/v5/pgxpool"

	"perimeter-scanner/infrastructure/logger"
	"perimeter-scanner/internal/adapter/masscan"
	"perimeter-scanner/internal/adapter/nmap"
	"perimeter-scanner/internal/adapter/postgres"
	"perimeter-scanner/internal/adapter/telegram"
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

	masscanScanner := masscan.NewScannerAdapter("", cfg.Scanner.Rate, cfg.Scanner.Interface, log)
	nmapEnricher := nmap.NewEnricherAdapter(log)
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
		postgresClient,
		telegramNotifier,
		log,
		cfg.Application.WorkerCount,
	)

	log.Info("Perimeter scanner architecture initialized successfully. Launching scan...")

	if err := perimeterScanner.Execute(ctx, cfg.Scanner.Targets, cfg.Scanner.Ports); err != nil {
		return fmt.Errorf("scanner execution failed: %w", err)
	}

	log.Info("Scan session completed successfully. All threats evaluated.")
	return nil
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
