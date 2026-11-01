package tests

import (
	"context"
	"testing"
	"time"

	"github.com/cicekhasann/cvegrid/internal/database"
	"github.com/cicekhasann/cvegrid/internal/model"
)

func setupTestDB(t *testing.T) *database.Repository {
	t.Helper()
	db, err := database.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return database.NewRepository(db)
}

func TestRepository_UpsertAndQuery(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	testItems := []model.Vulnerability{
		{
			CVEID:              "CVE-2024-0001",
			Vendor:             "Linux",
			Product:            "Kernel",
			Title:              "Linux Kernel BPF Privilege Escalation",
			Description:        "Local privilege escalation in Linux kernel eBPF verifier.",
			DateAdded:          "2024-01-10",
			RequiredAction:     "Update Linux kernel to 6.6.12",
			Category:           model.CategoryKernelOS,
			Severity:           model.SeverityCritical,
			Score:              9.8,
			Vector:             model.VectorLocalPrivesc,
			Source:             "CISA KEV",
			CWEID:              "CWE-787",
			EPSSScore:          0.45,
			EPSSPercentile:     0.75,
			RansomwareCampaign: 0,
			CVSSVector:         "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			RemediationNotes:   "Due: 2024-01-30",
			CreatedAt:          time.Now().UTC(),
		},
		{
			CVEID:              "CVE-2024-0002",
			Vendor:             "Fortinet",
			Product:            "FortiOS",
			Title:              "Fortinet FortiOS SSL-VPN Pre-auth RCE",
			Description:        "Remote code execution in FortiOS SSL-VPN web interface.",
			DateAdded:          "2024-01-15",
			RequiredAction:     "Apply vendor patch immediately",
			Category:           model.CategoryFirewallNet,
			Severity:           model.SeverityCritical,
			Score:              9.8,
			Vector:             model.VectorNetworkRemote,
			Source:             "CISA KEV",
			CWEID:              "CWE-78",
			EPSSScore:          0.94,
			EPSSPercentile:     0.98,
			RansomwareCampaign: 1,
			CVSSVector:         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			RemediationNotes:   "Due: 2024-01-22",
			ExecutiveSummary:   "Fortinet FortiOS SSL-VPN allows pre-auth RCE. DANGER: Ransomware weaponized.",
			Urgency:            "IMMEDIATE ACTION REQUIRED",
			ExploitStatus:      "EXPLOITED TODAY",
			ActionSummary:      "PATCH IMMEDIATELY",
			CWEDescription:     "OS Command Injection: Arbitrary commands executed in shell.",
			Articles: []model.CuratedArticle{
				{Title: "BleepingComputer: Fortinet Exploit", URL: "https://bleepingcomputer.com/fortinet", Domain: "bleepingcomputer.com", Category: "NEWS", Badge: "📰 News"},
			},
			CreatedAt: time.Now().UTC(),
		},
		{
			CVEID:              "CVE-2024-0003",
			Vendor:             "Apache",
			Product:            "HTTP Server",
			Title:              "Apache HTTP Server Path Traversal",
			Description:        "Path traversal flaw in mod_proxy.",
			DateAdded:          "2024-01-05",
			RequiredAction:     "Upgrade to Apache 2.4.58",
			Category:           model.CategoryServicesApps,
			Severity:           model.SeverityHigh,
			Score:              7.5,
			Vector:             model.VectorNetworkRemote,
			Source:             "CISA KEV",
			CWEID:              "CWE-22",
			EPSSScore:          0.65,
			EPSSPercentile:     0.82,
			RansomwareCampaign: 1,
			CVSSVector:         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			RemediationNotes:   "Due: 2024-01-29",
			CreatedAt:          time.Now().UTC(),
		},
	}

	// 1. Upsert items
	if err := repo.UpsertBatch(ctx, testItems); err != nil {
		t.Fatalf("failed to upsert batch: %v", err)
	}

	// 2. Query all items (chronological order)
	all, err := repo.GetVulnerabilities(ctx, database.FilterOptions{
		Category: model.CategoryAll,
	})
	if err != nil {
		t.Fatalf("failed to query all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 items, got %d", len(all))
	}
	// Verify chronological descending sort: 2024-01-15 first, then 2024-01-10, then 2024-01-05
	if all[0].CVEID != "CVE-2024-0002" {
		t.Errorf("expected first item to be CVE-2024-0002, got %s", all[0].CVEID)
	}
	if all[0].CWEID != "CWE-78" || all[0].RansomwareCampaign != 1 {
		t.Errorf("expected CWE-78 and Ransomware 1, got %s and %d", all[0].CWEID, all[0].RansomwareCampaign)
	}
	if all[0].Urgency != "IMMEDIATE ACTION REQUIRED" {
		t.Errorf("expected urgency IMMEDIATE ACTION REQUIRED, got %s", all[0].Urgency)
	}
	if len(all[0].Articles) != 1 || all[0].Articles[0].Domain != "bleepingcomputer.com" {
		t.Errorf("expected 1 article with domain bleepingcomputer.com, got %v", all[0].Articles)
	}

	// 3. Filter by category
	kernelItems, err := repo.GetVulnerabilities(ctx, database.FilterOptions{
		Category: model.CategoryKernelOS,
	})
	if err != nil {
		t.Fatalf("failed to query by category: %v", err)
	}
	if len(kernelItems) != 1 || kernelItems[0].CVEID != "CVE-2024-0001" {
		t.Errorf("expected 1 kernel item (CVE-2024-0001), got %v", kernelItems)
	}

	// 4. Filter by Ransomware only
	rwItems, err := repo.GetVulnerabilities(ctx, database.FilterOptions{
		RansomwareOnly: true,
	})
	if err != nil {
		t.Fatalf("failed to query ransomware items: %v", err)
	}
	if len(rwItems) != 2 {
		t.Errorf("expected 2 ransomware items, got %d", len(rwItems))
	}

	// 5. Sort by EPSS descending
	epssItems, err := repo.GetVulnerabilities(ctx, database.FilterOptions{
		SortBy: "epss_desc",
	})
	if err != nil {
		t.Fatalf("failed to query sorted by epss: %v", err)
	}
	if len(epssItems) != 3 || epssItems[0].CVEID != "CVE-2024-0002" || epssItems[2].CVEID != "CVE-2024-0001" {
		t.Errorf("expected epss descending sort (0002 -> 0003 -> 0001), got %v", epssItems)
	}

	// 6. Live search
	searchItems, err := repo.GetVulnerabilities(ctx, database.FilterOptions{
		SearchQuery: "fortinet",
	})
	if err != nil {
		t.Fatalf("failed to search: %v", err)
	}
	if len(searchItems) != 1 || searchItems[0].CVEID != "CVE-2024-0002" {
		t.Errorf("expected search result for 'fortinet' to yield CVE-2024-0002, got %v", searchItems)
	}

	// 7. Upsert idempotency and update
	updatedItem := testItems[0]
	updatedItem.Title = "Updated Title"
	if err := repo.UpsertBatch(ctx, []model.Vulnerability{updatedItem}); err != nil {
		t.Fatalf("failed to upsert update: %v", err)
	}

	res, err := repo.GetVulnerabilities(ctx, database.FilterOptions{SearchQuery: "CVE-2024-0001"})
	if err != nil || len(res) == 0 {
		t.Fatalf("failed to query updated item: %v", err)
	}
	if res[0].Title != "Updated Title" {
		t.Errorf("expected title to be 'Updated Title', got %q", res[0].Title)
	}
}

func TestRepository_StatsAndSyncMetadata(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Initially empty
	if count := repo.Count(); count != 0 {
		t.Errorf("expected initial Count() == 0, got %d", count)
	}

	stats, err := repo.GetStats(ctx)
	if err != nil {
		t.Fatalf("failed to get empty stats: %v", err)
	}
	if stats.TotalRecords != 0 || stats.CriticalCount != 0 {
		t.Errorf("expected 0 stats, got %+v", stats)
	}
	if stats.LastSync != "NEVER" {
		t.Errorf("expected initial last sync to be NEVER, got %q", stats.LastSync)
	}

	// Set last sync
	testTime := "2024-01-15 12:00:00 UTC"
	if err := repo.SetLastSync(ctx, testTime); err != nil {
		t.Fatalf("failed to set last sync: %v", err)
	}
	syncTime, err := repo.GetLastSync(ctx)
	if err != nil || syncTime != testTime {
		t.Errorf("expected sync time %q, got %q (err: %v)", testTime, syncTime, err)
	}

	// Insert items with varying scores
	items := []model.Vulnerability{
		{CVEID: "CVE-1", Vendor: "V1", Product: "P1", Title: "T1", Description: "D1", DateAdded: "2024-01-01", Category: model.CategoryOther, Severity: model.SeverityCritical, Score: 9.8, Vector: model.VectorNetworkRemote, Source: "CISA", RansomwareCampaign: 1, EPSSScore: 0.90},
		{CVEID: "CVE-2", Vendor: "V2", Product: "P2", Title: "T2", Description: "D2", DateAdded: "2024-01-02", Category: model.CategoryOther, Severity: model.SeverityHigh, Score: 7.5, Vector: model.VectorNetworkRemote, Source: "CISA", RansomwareCampaign: 1, EPSSScore: 0.60},
		{CVEID: "CVE-3", Vendor: "V3", Product: "P3", Title: "T3", Description: "D3", DateAdded: "2024-01-03", Category: model.CategoryOther, Severity: model.SeverityMedium, Score: 5.5, Vector: model.VectorLocalInternal, Source: "CISA", RansomwareCampaign: 0, EPSSScore: 0.30},
	}
	if err := repo.UpsertBatch(ctx, items); err != nil {
		t.Fatalf("failed to upsert batch: %v", err)
	}

	if count := repo.Count(); count != 3 {
		t.Errorf("expected Count() == 3, got %d", count)
	}

	stats, err = repo.GetStats(ctx)
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}
	if stats.TotalRecords != 3 {
		t.Errorf("expected 3 total records, got %d", stats.TotalRecords)
	}
	if stats.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", stats.CriticalCount)
	}
	if stats.HighCount != 1 {
		t.Errorf("expected 1 high, got %d", stats.HighCount)
	}
	if stats.MediumCount != 1 {
		t.Errorf("expected 1 medium, got %d", stats.MediumCount)
	}
	if stats.RansomwareCount != 2 {
		t.Errorf("expected 2 ransomware records, got %d", stats.RansomwareCount)
	}
	if stats.AvgEPSS < 0.59 || stats.AvgEPSS > 0.61 {
		t.Errorf("expected avg epss around 0.60, got %f", stats.AvgEPSS)
	}
	if stats.EPSSCritical != 1 || stats.EPSSHigh != 1 || stats.EPSSLow != 1 {
		t.Errorf("expected 1 critical, 1 high, 1 low EPSS distribution, got crit=%d high=%d low=%d", stats.EPSSCritical, stats.EPSSHigh, stats.EPSSLow)
	}
	if stats.LastSync != testTime {
		t.Errorf("expected last sync %q, got %q", testTime, stats.LastSync)
	}
}
