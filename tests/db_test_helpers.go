//go:build integration

package tests

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	postgresrepo "perimeter-scanner/internal/adapter/postgres"
)

// Helpers

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set; skipping, run via docker-compose.test.yml", key)
	}
	return v
}

// DB setup

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool, err := pgxpool.New(context.Background(), requireEnv(t, "TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("failed to connect to postgres: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	return pool
}

func newTestRepo(t *testing.T, pool *pgxpool.Pool) *postgresrepo.RepositoryAdapter {
	t.Helper()

	repo, err := postgresrepo.NewDBRepository(context.Background(), pool)
	if err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}

	return repo
}

// cleanDB truncates all scan data and the vulnerability catalog.
func cleanDB(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	_, err := pool.Exec(context.Background(), `
		TRUNCATE TABLE host_scans, vulnerabilities
		RESTART IDENTITY
		CASCADE
	`)
	if err != nil {
		t.Fatalf("cleanDB: %v", err)
	}
}
