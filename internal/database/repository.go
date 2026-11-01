package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cicekhasann/cvegrid/internal/model"
)

// FilterOptions specifies query filters for threat records.
type FilterOptions struct {
	Category       model.Category
	Severity       model.Severity
	RansomwareOnly bool
	SearchQuery    string
	SortBy         string // date_desc, date_asc, score_desc, score_asc, epss_desc, vendor_asc
	Limit          int
	Offset         int
}

// Repository handles thread-safe data operations on the vulnerabilities store.
type Repository struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewRepository initializes a Repository with the given database handle.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// UpsertBatch inserts or updates a batch of vulnerabilities in a single transaction.
func (r *Repository) UpsertBatch(ctx context.Context, items []model.Vulnerability) error {
	if len(items) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO vulnerabilities (
			cve_id, vendor, product, title, description,
			date_added, required_action, category, severity,
			score, vector, source, cwe_id, epss_score,
			epss_percentile, ransomware_campaign, cvss_vector,
			remediation_notes, executive_summary, urgency,
			exploit_status, action_summary, cwe_description,
			articles_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			vendor = excluded.vendor,
			product = excluded.product,
			title = excluded.title,
			description = excluded.description,
			date_added = excluded.date_added,
			required_action = excluded.required_action,
			category = excluded.category,
			severity = excluded.severity,
			score = excluded.score,
			vector = excluded.vector,
			source = excluded.source,
			cwe_id = excluded.cwe_id,
			epss_score = excluded.epss_score,
			epss_percentile = excluded.epss_percentile,
			ransomware_campaign = excluded.ransomware_campaign,
			cvss_vector = excluded.cvss_vector,
			remediation_notes = excluded.remediation_notes,
			executive_summary = excluded.executive_summary,
			urgency = excluded.urgency,
			exploit_status = excluded.exploit_status,
			action_summary = excluded.action_summary,
			cwe_description = excluded.cwe_description,
			articles_json = excluded.articles_json
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare upsert statement: %w", err)
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for _, item := range items {
		createdAt := item.CreatedAt
		if createdAt.IsZero() {
			createdAt = now
		}
		cweID := item.CWEID
		if cweID == "" {
			cweID = "N/A"
		}

		articlesBytes, _ := json.Marshal(item.Articles)
		if len(articlesBytes) == 0 {
			articlesBytes = []byte("[]")
		}

		_, err := stmt.ExecContext(ctx,
			item.CVEID,
			item.Vendor,
			item.Product,
			item.Title,
			item.Description,
			item.DateAdded,
			item.RequiredAction,
			string(item.Category),
			string(item.Severity),
			item.Score,
			string(item.Vector),
			item.Source,
			cweID,
			item.EPSSScore,
			item.EPSSPercentile,
			item.RansomwareCampaign,
			item.CVSSVector,
			item.RemediationNotes,
			item.ExecutiveSummary,
			item.Urgency,
			item.ExploitStatus,
			item.ActionSummary,
			item.CWEDescription,
			string(articlesBytes),
			createdAt,
		)
		if err != nil {
			return fmt.Errorf("failed to execute upsert for %s: %w", item.CVEID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func buildFilterQuery(filter FilterOptions) (string, []any) {
	var conditions []string
	var args []any

	if filter.Category != "" && filter.Category != model.CategoryAll {
		conditions = append(conditions, "category = ?")
		args = append(args, string(filter.Category))
	}

	if filter.Severity != "" && filter.Severity != model.SeverityAll {
		conditions = append(conditions, "severity = ?")
		args = append(args, string(filter.Severity))
	}

	if filter.RansomwareOnly {
		conditions = append(conditions, "ransomware_campaign = 1")
	}

	search := strings.TrimSpace(filter.SearchQuery)
	if search != "" {
		likePattern := "%" + search + "%"
		conditions = append(conditions, "(cve_id LIKE ? OR vendor LIKE ? OR product LIKE ? OR title LIKE ? OR cwe_id LIKE ?)")
		args = append(args, likePattern, likePattern, likePattern, likePattern, likePattern)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	return whereClause, args
}

// CountFiltered returns total matching records for given filter options.
func (r *Repository) CountFiltered(ctx context.Context, filter FilterOptions) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	whereClause, args := buildFilterQuery(filter)
	query := "SELECT COUNT(*) FROM vulnerabilities" + whereClause

	var count int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count filtered vulnerabilities: %w", err)
	}
	return count, nil
}

// GetVulnerabilities retrieves records matching the filter options.
func (r *Repository) GetVulnerabilities(ctx context.Context, filter FilterOptions) ([]model.Vulnerability, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	whereClause, args := buildFilterQuery(filter)

	orderClause := " ORDER BY date_added DESC, cve_id DESC"
	switch filter.SortBy {
	case "date_asc":
		orderClause = " ORDER BY date_added ASC, cve_id ASC"
	case "score_desc":
		orderClause = " ORDER BY score DESC, date_added DESC"
	case "score_asc":
		orderClause = " ORDER BY score ASC, date_added DESC"
	case "epss_desc":
		orderClause = " ORDER BY epss_score DESC, date_added DESC"
	case "vendor_asc":
		orderClause = " ORDER BY vendor ASC, product ASC"
	}

	query := `
		SELECT
			cve_id, vendor, product, title, description, date_added,
			required_action, category, severity, score, vector, source,
			cwe_id, epss_score, epss_percentile, ransomware_campaign,
			cvss_vector, remediation_notes, executive_summary, urgency,
			exploit_status, action_summary, cwe_description, articles_json,
			created_at
		FROM vulnerabilities` + whereClause + orderClause

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", filter.Offset)
		}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var result []model.Vulnerability
	for rows.Next() {
		var item model.Vulnerability
		var cat, sev, vec, articlesJSON string
		err := rows.Scan(
			&item.CVEID,
			&item.Vendor,
			&item.Product,
			&item.Title,
			&item.Description,
			&item.DateAdded,
			&item.RequiredAction,
			&cat,
			&sev,
			&item.Score,
			&vec,
			&item.Source,
			&item.CWEID,
			&item.EPSSScore,
			&item.EPSSPercentile,
			&item.RansomwareCampaign,
			&item.CVSSVector,
			&item.RemediationNotes,
			&item.ExecutiveSummary,
			&item.Urgency,
			&item.ExploitStatus,
			&item.ActionSummary,
			&item.CWEDescription,
			&articlesJSON,
			&item.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		item.Category = model.Category(cat)
		item.Severity = model.Severity(sev)
		item.Vector = model.Vector(vec)
		if articlesJSON != "" && articlesJSON != "[]" {
			_ = json.Unmarshal([]byte(articlesJSON), &item.Articles)
		}
		result = append(result, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return result, nil
}

// GetStats returns aggregate CTI counters, EPSS metrics, and top vendors.
func (r *Repository) GetStats(ctx context.Context) (model.Stats, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var stats model.Stats

	query := `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN score >= 9.0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN score >= 7.0 AND score < 9.0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN score >= 4.0 AND score < 7.0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN score < 4.0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(ransomware_campaign), 0),
			COALESCE(AVG(epss_score), 0.0),
			COALESCE(SUM(CASE WHEN epss_score >= 0.80 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN epss_score >= 0.50 AND epss_score < 0.80 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN epss_score < 0.50 THEN 1 ELSE 0 END), 0)
		FROM vulnerabilities
	`
	err := r.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalRecords,
		&stats.CriticalCount,
		&stats.HighCount,
		&stats.MediumCount,
		&stats.LowCount,
		&stats.RansomwareCount,
		&stats.AvgEPSS,
		&stats.EPSSCritical,
		&stats.EPSSHigh,
		&stats.EPSSLow,
	)
	if err != nil {
		return stats, fmt.Errorf("failed to calculate stats: %w", err)
	}

	// Category counts
	catRows, err := r.db.QueryContext(ctx, `
		SELECT category, COUNT(*) as c
		FROM vulnerabilities
		GROUP BY category
		ORDER BY c DESC
	`)
	if err == nil {
		defer catRows.Close()
		for catRows.Next() {
			var cc model.CategoryCount
			if err := catRows.Scan(&cc.Category, &cc.Count); err == nil {
				stats.CategoryCounts = append(stats.CategoryCounts, cc)
			}
		}
	}

	// Vector counts
	vecRows, err := r.db.QueryContext(ctx, `
		SELECT vector, COUNT(*) as c
		FROM vulnerabilities
		GROUP BY vector
		ORDER BY c DESC
	`)
	if err == nil {
		defer vecRows.Close()
		for vecRows.Next() {
			var vc model.VectorCount
			if err := vecRows.Scan(&vc.Vector, &vc.Count); err == nil {
				stats.VectorCounts = append(stats.VectorCounts, vc)
			}
		}
	}

	// Top Affected Vendors
	vendorRows, err := r.db.QueryContext(ctx, `
		SELECT vendor, COUNT(*) as c
		FROM vulnerabilities
		WHERE vendor != ''
		GROUP BY vendor
		ORDER BY c DESC
		LIMIT 8
	`)
	if err == nil {
		defer vendorRows.Close()
		for vendorRows.Next() {
			var vc model.VendorCount
			if err := vendorRows.Scan(&vc.Vendor, &vc.Count); err == nil {
				stats.TopVendors = append(stats.TopVendors, vc)
			}
		}
	}

	lastSync, _ := r.GetLastSync(ctx)
	stats.LastSync = lastSync

	return stats, nil
}

// GetLastSync fetches the last successful sync timestamp.
func (r *Repository) GetLastSync(ctx context.Context) (string, error) {
	var value string
	err := r.db.QueryRowContext(ctx, "SELECT value FROM sync_metadata WHERE key = 'last_sync'").Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "NEVER", nil
		}
		return "", err
	}
	return value, nil
}

// SetLastSync updates the last successful sync timestamp.
func (r *Repository) SetLastSync(ctx context.Context, value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sync_metadata (key, value, updated_at)
		VALUES ('last_sync', ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
	`, value)
	if err != nil {
		return fmt.Errorf("failed to record last sync: %w", err)
	}
	return nil
}

// Count returns the total number of vulnerability records.
func (r *Repository) Count(ctx ...context.Context) int {
	var c context.Context
	if len(ctx) > 0 && ctx[0] != nil {
		c = ctx[0]
	} else {
		var cancel context.CancelFunc
		c, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var count int
	_ = r.db.QueryRowContext(c, "SELECT COUNT(*) FROM vulnerabilities").Scan(&count)
	return count
}
