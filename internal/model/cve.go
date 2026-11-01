package model

import (
	"time"
)

// Category represents high-level classification of vulnerabilities.
type Category string

const (
	CategoryAll          Category = "ALL"
	CategoryKernelOS     Category = "KERNEL & OS"
	CategoryFirewallNet  Category = "FIREWALL & NET"
	CategoryMemorySafety Category = "MEMORY SAFETY"
	CategoryServicesApps Category = "SERVICES & APPS"
	CategoryOther        Category = "OTHER"
)

// Severity represents CVSS-derived impact levels.
type Severity string

const (
	SeverityAll      Severity = "ALL"
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Vector represents attack vector classification.
type Vector string

const (
	VectorNetworkRemote Vector = "NETWORK / REMOTE"
	VectorLocalPrivesc  Vector = "LOCAL / PRIVESC"
	VectorLocalInternal Vector = "LOCAL / INTERNAL"
)

// CuratedArticle represents a high-value threat intelligence reading reference.
type CuratedArticle struct {
	Title    string `json:"title"`
	URL      string `json:"url"`
	Domain   string `json:"domain"`
	Category string `json:"category"` // "NEWS", "DEEP_DIVE", "ADVISORY"
	Badge    string `json:"badge"`    // "📰 News", "🔬 Deep Dive", "🛠️ Advisory"
}

// Vulnerability represents an enriched threat intelligence record.
type Vulnerability struct {
	CVEID              string           `json:"cve_id"`
	Vendor             string           `json:"vendor"`
	Product            string           `json:"product"`
	Title              string           `json:"title"`
	Description        string           `json:"description"`
	DateAdded          string           `json:"date_added"` // YYYY-MM-DD
	RequiredAction     string           `json:"required_action"`
	Category           Category         `json:"category"`
	Severity           Severity         `json:"severity"`
	Score              float64          `json:"score"`
	Vector             Vector           `json:"vector"`
	Source             string           `json:"source"`
	CWEID              string           `json:"cwe_id"`
	EPSSScore          float64          `json:"epss_score"`
	EPSSPercentile     float64          `json:"epss_percentile"`
	RansomwareCampaign int              `json:"ransomware_campaign"` // 1 = Yes, 0 = No
	CVSSVector         string           `json:"cvss_vector"`
	RemediationNotes   string           `json:"remediation_notes"`
	DueDate            string           `json:"due_date,omitempty"`
	ExecutiveSummary   string           `json:"executive_summary"`
	Urgency            string           `json:"urgency"`        // "IMMEDIATE ACTION REQUIRED", "SCHEDULE MAINTENANCE", "MONITOR"
	ExploitStatus      string           `json:"exploit_status"` // "EXPLOITED TODAY", "NO KNOWN EXPLOIT"
	ActionSummary      string           `json:"action_summary"` // "PATCH IMMEDIATELY", "ISOLATE PORT", "APPLY VENDOR MITIGATION", "TEMPORARY WORKAROUND"
	CWEDescription     string           `json:"cwe_description"`
	Articles           []CuratedArticle `json:"articles"`
	CreatedAt          time.Time        `json:"created_at"`
}

// VendorCount represents count of vulnerabilities for a vendor.
type VendorCount struct {
	Vendor string `json:"vendor"`
	Count  int    `json:"count"`
}

// CategoryCount represents count per category.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// VectorCount represents count per attack vector.
type VectorCount struct {
	Vector string `json:"vector"`
	Count  int    `json:"count"`
}

// Stats holds aggregate telemetry counters for the CTI HUD and Dashboard.
type Stats struct {
	TotalRecords    int             `json:"total_records"`
	CriticalCount   int             `json:"critical_count"`
	HighCount       int             `json:"high_count"`
	MediumCount     int             `json:"medium_count"`
	LowCount        int             `json:"low_count"`
	RansomwareCount int             `json:"ransomware_count"`
	AvgEPSS         float64         `json:"avg_epss"`
	EPSSCritical    int             `json:"epss_critical"` // > 0.80
	EPSSHigh        int             `json:"epss_high"`     // 0.50 - 0.80
	EPSSLow         int             `json:"epss_low"`      // < 0.50
	LastSync        string          `json:"last_sync"`
	TopVendors      []VendorCount   `json:"top_vendors,omitempty"`
	CategoryCounts  []CategoryCount `json:"category_counts,omitempty"`
	VectorCounts    []VectorCount   `json:"vector_counts,omitempty"`
}
