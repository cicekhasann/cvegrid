package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cicekhasann/cvegrid/internal/database"
	"github.com/cicekhasann/cvegrid/internal/ingestion"
	"github.com/cicekhasann/cvegrid/internal/model"
	"github.com/cicekhasann/cvegrid/internal/web"
)

func TestWebServer_Endpoints(t *testing.T) {
	db, err := database.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	defer db.Close()

	repo := database.NewRepository(db)
	ctx := context.Background()

	testItems := []model.Vulnerability{
		{
			CVEID:              "CVE-2024-1001",
			Vendor:             "Fortinet",
			Product:            "FortiOS",
			Title:              "Fortinet SSL-VPN RCE",
			Description:        "Remote code execution flaw in SSL-VPN",
			DateAdded:          "2024-01-10",
			Category:           model.CategoryFirewallNet,
			Severity:           model.SeverityCritical,
			Score:              9.8,
			Vector:             model.VectorNetworkRemote,
			Source:             "CISA KEV",
			CWEID:              "CWE-78",
			EPSSScore:          0.95,
			EPSSPercentile:     0.99,
			RansomwareCampaign: 1,
			CVSSVector:         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			RemediationNotes:   "Due: 2024-01-20",
			ExecutiveSummary:   "Fortinet FortiOS SSL-VPN allows remote attackers to execute arbitrary code. DANGER: Ransomware weaponized.",
			Urgency:            "IMMEDIATE ACTION REQUIRED",
			ExploitStatus:      "EXPLOITED TODAY",
			ActionSummary:      "PATCH IMMEDIATELY",
			CWEDescription:     "OS Command Injection: Unsanitized input is passed directly to the operating system shell.",
			Articles: []model.CuratedArticle{
				{Title: "BleepingComputer: Fortinet Active Exploits", URL: "https://www.bleepingcomputer.com/tag/cve-2024-1001/", Domain: "bleepingcomputer.com", Category: "NEWS", Badge: "📰 News"},
			},
			CreatedAt: time.Now().UTC(),
		},
		{
			CVEID:              "CVE-2024-1002",
			Vendor:             "Linux",
			Product:            "Kernel",
			Title:              "Linux Kernel PrivEsc",
			Description:        "Local privilege escalation in kernel",
			DateAdded:          "2024-01-12",
			Category:           model.CategoryKernelOS,
			Severity:           model.SeverityHigh,
			Score:              7.5,
			Vector:             model.VectorLocalPrivesc,
			Source:             "CISA KEV",
			CWEID:              "CWE-416",
			EPSSScore:          0.40,
			EPSSPercentile:     0.70,
			RansomwareCampaign: 0,
			CVSSVector:         "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			RemediationNotes:   "Due: 2024-02-01",
			CreatedAt:          time.Now().UTC(),
		},
	}
	if err := repo.UpsertBatch(ctx, testItems); err != nil {
		t.Fatalf("failed to upsert: %v", err)
	}

	client := ingestion.NewHTTPClient(ingestion.DefaultTimeout)
	syncer := ingestion.NewSynchronizer(client, repo, "")
	server := web.NewServer(repo, syncer, 8080)
	handler := server.Handler()

	// 1. Test Static Asset Serving (index.html)
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for index.html, got %d", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "CVEGRID") {
			t.Errorf("expected index.html to contain 'CVEGRID', got %s", body)
		}
	}

	// 2. Test GET /api/stats
	{
		req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for /api/stats, got %d", w.Code)
		}

		var stats model.Stats
		if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
			t.Fatalf("failed to parse /api/stats JSON: %v", err)
		}
		if stats.TotalRecords != 2 {
			t.Errorf("expected total_records 2, got %d", stats.TotalRecords)
		}
		if stats.CriticalCount != 1 {
			t.Errorf("expected critical_count 1, got %d", stats.CriticalCount)
		}
		if stats.HighCount != 1 {
			t.Errorf("expected high_count 1, got %d", stats.HighCount)
		}
		if stats.RansomwareCount != 1 {
			t.Errorf("expected ransomware_count 1, got %d", stats.RansomwareCount)
		}
		if stats.AvgEPSS < 0.6 || stats.AvgEPSS > 0.7 {
			t.Errorf("expected avg_epss around 0.675, got %f", stats.AvgEPSS)
		}
	}

	// 3. Test GET /api/vulnerabilities with category and ransomware filter
	{
		// Test category filter
		req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities?category=FIREWALL%20%26%20NET", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for /api/vulnerabilities, got %d", w.Code)
		}

		var resp struct {
			Items      []model.Vulnerability `json:"items"`
			Total      int                   `json:"total"`
			Page       int                   `json:"page"`
			TotalPages int                   `json:"total_pages"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse /api/vulnerabilities JSON: %v", err)
		}
		if resp.Total != 1 || len(resp.Items) != 1 {
			t.Errorf("expected 1 firewall vulnerability, got total=%d len=%d", resp.Total, len(resp.Items))
		}
		if resp.Items[0].CVEID != "CVE-2024-1001" {
			t.Errorf("expected CVE-2024-1001, got %s", resp.Items[0].CVEID)
		}
		if resp.Items[0].CWEID != "CWE-78" || resp.Items[0].RansomwareCampaign != 1 {
			t.Errorf("expected CWE-78 and RansomwareCampaign 1, got %s and %d", resp.Items[0].CWEID, resp.Items[0].RansomwareCampaign)
		}
		if resp.Items[0].Urgency != "IMMEDIATE ACTION REQUIRED" {
			t.Errorf("expected urgency IMMEDIATE ACTION REQUIRED, got %s", resp.Items[0].Urgency)
		}
		if !strings.Contains(resp.Items[0].ExecutiveSummary, "DANGER: Ransomware weaponized") {
			t.Errorf("expected executive summary in response, got %s", resp.Items[0].ExecutiveSummary)
		}
		if len(resp.Items[0].Articles) != 1 || resp.Items[0].Articles[0].Domain != "bleepingcomputer.com" {
			t.Errorf("expected articles to contain bleepingcomputer.com, got %v", resp.Items[0].Articles)
		}

		// Test ransomware_only filter
		reqRW := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities?ransomware_only=true", nil)
		wRW := httptest.NewRecorder()
		handler.ServeHTTP(wRW, reqRW)
		if wRW.Code != http.StatusOK {
			t.Fatalf("expected 200 for ransomware filter, got %d", wRW.Code)
		}
		var rwResp struct {
			Items []model.Vulnerability `json:"items"`
			Total int                   `json:"total"`
		}
		if err := json.Unmarshal(wRW.Body.Bytes(), &rwResp); err != nil {
			t.Fatalf("failed to parse ransomware JSON: %v", err)
		}
		if rwResp.Total != 1 || len(rwResp.Items) != 1 || rwResp.Items[0].CVEID != "CVE-2024-1001" {
			t.Errorf("expected 1 ransomware item (CVE-2024-1001), got %v", rwResp)
		}
	}

	// 4. Test POST /api/sync
	{
		req := httptest.NewRequest(http.MethodPost, "/api/sync", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for /api/sync, got %d", w.Code)
		}

		var syncResp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &syncResp); err != nil {
			t.Fatalf("failed to parse /api/sync JSON: %v", err)
		}
		if syncResp["status"] != "sync_started" && syncResp["status"] != "already_syncing" {
			t.Errorf("unexpected sync status: %v", syncResp)
		}
	}
}
