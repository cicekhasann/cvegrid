package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    date_added TEXT NOT NULL,
    required_action TEXT,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    score REAL NOT NULL,
    vector TEXT NOT NULL,
    source TEXT NOT NULL,
    cwe_id TEXT DEFAULT 'N/A',
    epss_score REAL DEFAULT 0.0,
    epss_percentile REAL DEFAULT 0.0,
    ransomware_campaign INTEGER DEFAULT 0,
    cvss_vector TEXT DEFAULT '',
    remediation_notes TEXT DEFAULT '',
    executive_summary TEXT DEFAULT '',
    urgency TEXT DEFAULT 'MONITOR',
    exploit_status TEXT DEFAULT 'ACTIVE IN WILD',
    action_summary TEXT DEFAULT 'APPLY VENDOR PATCH',
    cwe_description TEXT DEFAULT '',
    articles_json TEXT DEFAULT '[]',
    ecosystem TEXT DEFAULT '',
    tech_tags TEXT DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sync_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cve_date ON vulnerabilities(date_added DESC);
CREATE INDEX IF NOT EXISTS idx_cve_category ON vulnerabilities(category);
CREATE INDEX IF NOT EXISTS idx_cve_search ON vulnerabilities(cve_id, vendor, product);
CREATE INDEX IF NOT EXISTS idx_cve_ransomware ON vulnerabilities(ransomware_campaign);
CREATE INDEX IF NOT EXISTS idx_cve_epss ON vulnerabilities(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_cve_ecosystem ON vulnerabilities(ecosystem);
`

// migrationColumns defines columns added in later versions to ensure graceful upgrades.
var migrationColumns = []string{
	"ALTER TABLE vulnerabilities ADD COLUMN cwe_id TEXT DEFAULT 'N/A'",
	"ALTER TABLE vulnerabilities ADD COLUMN epss_score REAL DEFAULT 0.0",
	"ALTER TABLE vulnerabilities ADD COLUMN epss_percentile REAL DEFAULT 0.0",
	"ALTER TABLE vulnerabilities ADD COLUMN ransomware_campaign INTEGER DEFAULT 0",
	"ALTER TABLE vulnerabilities ADD COLUMN cvss_vector TEXT DEFAULT ''",
	"ALTER TABLE vulnerabilities ADD COLUMN remediation_notes TEXT DEFAULT ''",
	"ALTER TABLE vulnerabilities ADD COLUMN executive_summary TEXT DEFAULT ''",
	"ALTER TABLE vulnerabilities ADD COLUMN urgency TEXT DEFAULT 'MONITOR'",
	"ALTER TABLE vulnerabilities ADD COLUMN exploit_status TEXT DEFAULT 'ACTIVE IN WILD'",
	"ALTER TABLE vulnerabilities ADD COLUMN action_summary TEXT DEFAULT 'APPLY VENDOR PATCH'",
	"ALTER TABLE vulnerabilities ADD COLUMN cwe_description TEXT DEFAULT ''",
	"ALTER TABLE vulnerabilities ADD COLUMN articles_json TEXT DEFAULT '[]'",
	"ALTER TABLE vulnerabilities ADD COLUMN ecosystem TEXT DEFAULT ''",
	"ALTER TABLE vulnerabilities ADD COLUMN tech_tags TEXT DEFAULT '[]'",
	"CREATE INDEX IF NOT EXISTS idx_cve_ecosystem ON vulnerabilities(ecosystem)",
}

// OpenDB opens a connection to SQLite at the given path (or :memory:) and applies the schema.
func OpenDB(dsn string) (*sql.DB, error) {
	connStr := dsn
	if dsn != ":memory:" && dsn != "file::memory:?cache=shared" {
		connStr = fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dsn)
	}

	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	// Apply column migrations gracefully if upgrading from older schema
	for _, migration := range migrationColumns {
		_, _ = db.ExecContext(ctx, migration)
	}

	return db, nil
}
