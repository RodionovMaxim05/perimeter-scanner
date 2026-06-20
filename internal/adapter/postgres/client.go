package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"perimeter-scanner/internal/domain"
)

// RepositoryAdapter implements domain.ResultRepository backed by PostgreSQL.
// It uses sqlc-generated queries and pgxpool for connection management.
type RepositoryAdapter struct {
	pool    *pgxpool.Pool
	queries *Queries
}

// NewDBRepository constructs a RepositoryAdapter and preloads.
func NewDBRepository(ctx context.Context, pool *pgxpool.Pool) (*RepositoryAdapter, error) {
	return &RepositoryAdapter{
		pool:    pool,
		queries: New(pool),
	}, nil
}

// GetPreviousResult returns the most recent scan result for the given IP.
// Returns (_, false, nil) when no previous scan exists for that host.
func (ra *RepositoryAdapter) GetPreviousResult(ctx context.Context, ip string) (domain.HostScanResult, bool, error) {
	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return domain.HostScanResult{}, false, fmt.Errorf("invalid ip format: %w", err)
	}

	host, err := ra.queries.GetLastHostScan(ctx, parsedIP)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.HostScanResult{}, false, nil
		}
		return domain.HostScanResult{}, false, fmt.Errorf("failed to get last host scan: %w", err)
	}

	rows, err := ra.queries.GetServicesWithVulnerabilities(ctx, host.ID)
	if err != nil {
		return domain.HostScanResult{}, false, fmt.Errorf("failed to get services with vulns: %w", err)
	}

	serviceInfos := buildServicesFromRows(rows)

	return domain.HostScanResult{
		IP:       host.Ip.String(),
		ScanTime: host.ScanTime.Time,
		Services: serviceInfos,
	}, true, nil
}

// buildServicesFromRows groups rows into a slice of ServiceInfo.
func buildServicesFromRows(rows []GetServicesWithVulnerabilitiesRow) []domain.ServiceInfo {
	servicesMap := make(map[int32]*domain.ServiceInfo)

	for _, row := range rows {
		svc, exists := servicesMap[row.ServiceID]
		if !exists {
			svc = &domain.ServiceInfo{
				Port:    int(row.Port),
				Proto:   row.Proto,
				Service: row.Service.String,
				Banner:  row.Banner.String,
				Version: row.Version.String,
				CPE:     row.Cpe.String,
			}
			servicesMap[row.ServiceID] = svc
		}

		if !row.Cve.Valid {
			// There are no vulnerabilities in the service
			continue
		}

		score, _ := row.Score.Float64Value()
		svc.Vulnerabilities = append(svc.Vulnerabilities, domain.Vulnerability{
			CVE:              row.Cve.String,
			Score:            score.Float64,
			Description:      row.Description.String,
			ExploitAvailable: row.ExploitAvailable.Bool,
			Link:             row.Link.String,
		})
	}

	result := make([]domain.ServiceInfo, 0, len(servicesMap))
	for _, svc := range servicesMap {
		result = append(result, *svc)
	}
	return result
}

// SaveResult persists a full host scan result in a single transaction.
// Vulnerabilities are upserted so the catalog stays up-to-date when scores
// or descriptions change between scans.
func (ra *RepositoryAdapter) SaveResult(ctx context.Context, result domain.HostScanResult) error {
	parsedIP, err := netip.ParseAddr(result.IP)
	if err != nil {
		return fmt.Errorf("invalid ip format: %w", err)
	}

	tx, err := ra.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	qtx := ra.queries.WithTx(tx)

	hostScanID, err := qtx.CreateHostScan(ctx, CreateHostScanParams{
		Ip:       parsedIP,
		ScanTime: pgtype.Timestamptz{Time: result.ScanTime, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("failed to create host scan: %w", err)
	}

	for _, svc := range result.Services {
		if err := ra.saveScanService(ctx, qtx, hostScanID, svc); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// saveScanService inserts one service row and links all its vulnerabilities.
func (ra *RepositoryAdapter) saveScanService(
	ctx context.Context,
	qtx *Queries,
	hostScanID int32,
	svc domain.ServiceInfo,
) error {
	serviceID, err := qtx.CreateService(ctx, CreateServiceParams{
		HostScanID: hostScanID,
		Port:       int32(svc.Port),
		Proto:      svc.Proto,
		Service:    pgtype.Text{String: svc.Service, Valid: svc.Service != ""},
		Banner:     pgtype.Text{String: svc.Banner, Valid: svc.Banner != ""},
		Version:    pgtype.Text{String: svc.Version, Valid: svc.Version != ""},
		Cpe:        pgtype.Text{String: svc.CPE, Valid: svc.CPE != ""},
	})
	if err != nil {
		return fmt.Errorf("create service %d/%s: %w", svc.Port, svc.Proto, err)
	}

	if len(svc.Vulnerabilities) == 0 {
		return nil
	}

	for _, vuln := range svc.Vulnerabilities {
		scoreNumeric, err := scoreToNumeric(vuln.Score)
		if err != nil {
			return fmt.Errorf("convert score for %s: %w", vuln.CVE, err)
		}

		vulnID, err := qtx.UpsertVulnerability(ctx, UpsertVulnerabilityParams{
			Cve:              vuln.CVE,
			Score:            scoreNumeric,
			Description:      pgtype.Text{String: vuln.Description, Valid: vuln.Description != ""},
			ExploitAvailable: vuln.ExploitAvailable,
			Link:             pgtype.Text{String: vuln.Link, Valid: vuln.Link != ""},
		})
		if err != nil {
			return fmt.Errorf("upsert vulnerability %s: %w", vuln.CVE, err)
		}

		if err := qtx.LinkServiceVuln(ctx, LinkServiceVulnParams{
			ServiceID:       serviceID,
			VulnerabilityID: vulnID,
		}); err != nil {
			return fmt.Errorf("link vuln %s to service %d: %w", vuln.CVE, serviceID, err)
		}
	}

	return nil
}

// scoreToNumeric converts a float64 CVSS score to pgtype.Numeric with one decimal place.
func scoreToNumeric(score float64) (pgtype.Numeric, error) {
	var n pgtype.Numeric
	err := n.Scan(fmt.Sprintf("%.1f", score))
	if err != nil {
		return pgtype.Numeric{}, err
	}
	return n, nil
}
