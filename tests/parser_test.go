package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/cicekhasann/cvegrid/internal/ingestion"
	"github.com/cicekhasann/cvegrid/internal/model"
)

const sampleKEVJSON = `{
  "title": "CISA Known Exploited Vulnerabilities Catalog",
  "catalogVersion": "2024.01.15",
  "dateReleased": "2024-01-15T00:00:00.000Z",
  "count": 4,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-21887",
      "vendorProject": "Ivanti",
      "product": "Connect Secure",
      "vulnerabilityName": "Ivanti Connect Secure Command Injection Vulnerability",
      "dateAdded": "2024-01-10",
      "shortDescription": "Ivanti Connect Secure contains a command injection vulnerability allowing an unauthenticated remote administrator to execute arbitrary commands.",
      "requiredAction": "Apply mitigations per vendor advisory.",
      "dueDate": "2024-01-22",
      "knownRansomwareCampaignUse": "Known",
      "notes": "https://nvd.nist.gov/vuln/detail/CVE-2024-21887"
    },
    {
      "cveID": "CVE-2023-38606",
      "vendorProject": "Apple",
      "product": "macOS",
      "vulnerabilityName": "Apple macOS Kernel State Modification Vulnerability",
      "dateAdded": "2023-07-24",
      "shortDescription": "Apple macOS kernel contains an issue where an app may be able to modify sensitive kernel state.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2023-08-14",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "https://nvd.nist.gov/vuln/detail/CVE-2023-38606"
    },
    {
      "cveID": "CVE-2023-28252",
      "vendorProject": "Microsoft",
      "product": "Windows Common Log File System",
      "vulnerabilityName": "Windows CLFS Out-of-Bounds Write Vulnerability",
      "dateAdded": "2023-04-11",
      "shortDescription": "Microsoft Windows Common Log File System driver contains an out-of-bounds write vulnerability that leads to privilege escalation.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2023-05-02",
      "knownRansomwareCampaignUse": "Known",
      "notes": "https://nvd.nist.gov/vuln/detail/CVE-2023-28252"
    },
    {
      "cveID": "CVE-2023-44487",
      "vendorProject": "Internet Engineering Task Force",
      "product": "HTTP/2",
      "vulnerabilityName": "HTTP/2 Rapid Reset Denial-of-Service Vulnerability",
      "dateAdded": "2023-10-10",
      "shortDescription": "The HTTP/2 protocol allows a denial of service attack via RST_STREAM frame floods on network interfaces.",
      "requiredAction": "Apply patches for web servers and proxies.",
      "dueDate": "2023-10-31",
      "knownRansomwareCampaignUse": "Known",
      "notes": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"
    }
  ]
}`

func TestParser_StreamParsing(t *testing.T) {
	reader := strings.NewReader(sampleKEVJSON)
	var items []model.Vulnerability

	count, err := ingestion.ParseKEVStream(reader, func(item model.Vulnerability) error {
		items = append(items, item)
		return nil
	})

	if err != nil {
		t.Fatalf("ParseKEVStream failed: %v", err)
	}

	if count != 4 || len(items) != 4 {
		t.Fatalf("expected 4 items, got count=%d len=%d", count, len(items))
	}

	// Item 1: Ivanti (unauthenticated remote command injection)
	ivanti := items[0]
	if ivanti.CVEID != "CVE-2024-21887" {
		t.Errorf("expected CVE-2024-21887, got %s", ivanti.CVEID)
	}
	if ivanti.Severity != model.SeverityCritical || ivanti.Score != 9.8 {
		t.Errorf("expected critical 9.8 for RCE/unauth, got %s %.1f", ivanti.Severity, ivanti.Score)
	}
	if ivanti.Vector != model.VectorNetworkRemote {
		t.Errorf("expected remote vector, got %s", ivanti.Vector)
	}
	if ivanti.RansomwareCampaign != 1 {
		t.Errorf("expected ransomware campaign flag 1 for Ivanti, got %d", ivanti.RansomwareCampaign)
	}
	if ivanti.CWEID != "CWE-78" {
		t.Errorf("expected CWE-78 for command injection, got %s", ivanti.CWEID)
	}
	if ivanti.EPSSScore < 0.85 {
		t.Errorf("expected high EPSS score (>0.85) for remote ransomware vuln, got %f", ivanti.EPSSScore)
	}
	if ivanti.DueDate != "2024-01-22" {
		t.Errorf("expected due date 2024-01-22, got %s", ivanti.DueDate)
	}
	if !strings.Contains(ivanti.RemediationNotes, "2024-01-22") {
		t.Errorf("expected remediation notes to contain due date, got %s", ivanti.RemediationNotes)
	}

	// Item 2: Apple macOS Kernel
	apple := items[1]
	if apple.Category != model.CategoryKernelOS {
		t.Errorf("expected KERNEL & OS category, got %s", apple.Category)
	}
	if apple.RansomwareCampaign != 0 {
		t.Errorf("expected ransomware campaign flag 0 for Apple, got %d", apple.RansomwareCampaign)
	}

	// Item 3: Windows CLFS Out-of-Bounds write (Memory Safety)
	win := items[2]
	if win.Category != model.CategoryMemorySafety {
		t.Errorf("expected MEMORY SAFETY category, got %s", win.Category)
	}
	if win.Vector != model.VectorLocalPrivesc {
		t.Errorf("expected LOCAL / PRIVESC vector, got %s", win.Vector)
	}
	if win.RansomwareCampaign != 1 {
		t.Errorf("expected ransomware campaign flag 1 for Windows CLFS, got %d", win.RansomwareCampaign)
	}
	if win.CWEID != "CWE-787" {
		t.Errorf("expected CWE-787 for out-of-bounds write, got %s", win.CWEID)
	}

	// Verify Story-Driven Human-Readable Fields on Ivanti
	if !strings.Contains(ivanti.ExecutiveSummary, "Ivanti Connect Secure contains a command injection") {
		t.Errorf("expected ExecutiveSummary to explain what is broken, got: %s", ivanti.ExecutiveSummary)
	}
	if !strings.Contains(ivanti.ExecutiveSummary, "DANGER: Actively weaponized in the wild by ransomware crews") {
		t.Errorf("expected ExecutiveSummary to explain danger, got: %s", ivanti.ExecutiveSummary)
	}
	if ivanti.Urgency != "IMMEDIATE ACTION REQUIRED" {
		t.Errorf("expected IMMEDIATE ACTION REQUIRED urgency, got: %s", ivanti.Urgency)
	}
	if ivanti.ExploitStatus != "EXPLOITED TODAY" {
		t.Errorf("expected EXPLOITED TODAY exploit status, got: %s", ivanti.ExploitStatus)
	}
	if len(ivanti.Articles) != 3 {
		t.Fatalf("expected 3 curated articles, got %d", len(ivanti.Articles))
	}
	if ivanti.Articles[0].Domain != "bleepingcomputer.com" {
		t.Errorf("expected first article domain bleepingcomputer.com, got %s", ivanti.Articles[0].Domain)
	}
	if ivanti.Articles[2].Domain != "nvd.nist.gov" {
		t.Errorf("expected third article domain nvd.nist.gov, got %s", ivanti.Articles[2].Domain)
	}
	if !strings.Contains(win.CWEDescription, "Out-of-bounds Write") {
		t.Errorf("expected CWE description to explain out-of-bounds write, got: %s", win.CWEDescription)
	}
}

func TestParser_CTIEnrichment(t *testing.T) {
	now := time.Now().UTC()

	// Test CWE Heuristics
	cweTests := []struct {
		desc     string
		expected string
	}{
		{"Contains a use-after-free flaw in memory manager", "CWE-416"},
		{"Vulnerable to SQL injection in login handler", "CWE-89"},
		{"Cross-site scripting flaw in search parameter", "CWE-79"},
		{"Buffer overflow allows arbitrary write", "CWE-120"},
		{"Allows directory traversal attack", "CWE-22"},
		{"Explicit reference to CWE-352 in description", "CWE-352"},
		{"Generic vulnerability with no known CWE pattern", "CWE-Other"},
	}

	for _, tt := range cweTests {
		item := ingestion.ClassifyRawKEV(ingestion.RawKEVItem{
			CVEID:            "CVE-TEST-CWE",
			ShortDescription: tt.desc,
		}, now)
		if item.CWEID != tt.expected {
			t.Errorf("for desc %q: expected CWE %s, got %s", tt.desc, tt.expected, item.CWEID)
		}
	}

	// Test EPSS Probability Calculation
	remoteRansomware := ingestion.ClassifyRawKEV(ingestion.RawKEVItem{
		CVEID:                      "CVE-TEST-EPSS-1",
		ShortDescription:           "Remote command injection via network HTTP endpoint",
		KnownRansomwareCampaignUse: "Known",
	}, now)
	if remoteRansomware.EPSSScore < 0.85 || remoteRansomware.EPSSScore > 1.0 {
		t.Errorf("expected high EPSS score between 0.85 and 1.0, got %f", remoteRansomware.EPSSScore)
	}
	if remoteRansomware.EPSSPercentile < 0.90 {
		t.Errorf("expected high percentile (>0.90), got %f", remoteRansomware.EPSSPercentile)
	}

	localOnly := ingestion.ClassifyRawKEV(ingestion.RawKEVItem{
		CVEID:                      "CVE-TEST-EPSS-2",
		ShortDescription:           "Internal null pointer dereference causes crash",
		KnownRansomwareCampaignUse: "Unknown",
	}, now)
	if localOnly.EPSSScore > 0.40 {
		t.Errorf("expected lower EPSS score for local crash, got %f", localOnly.EPSSScore)
	}
}

func TestParser_CategoryHeuristics(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name     string
		raw      ingestion.RawKEVItem
		expected model.Category
	}{
		{
			name: "Kernel & OS - Linux",
			raw: ingestion.RawKEVItem{
				CVEID:         "CVE-TEST-1",
				VendorProject: "Linux",
				Product:       "Linux Kernel",
			},
			expected: model.CategoryKernelOS,
		},
		{
			name: "Firewall & Net - Cisco",
			raw: ingestion.RawKEVItem{
				CVEID:         "CVE-TEST-2",
				VendorProject: "Cisco",
				Product:       "ASA Firewall VPN",
			},
			expected: model.CategoryFirewallNet,
		},
		{
			name: "Memory Safety - Buffer Overflow",
			raw: ingestion.RawKEVItem{
				CVEID:            "CVE-TEST-3",
				VendorProject:    "Generic",
				Product:          "Utility",
				ShortDescription: "Vulnerability caused by a heap buffer overflow in parser.",
			},
			expected: model.CategoryMemorySafety,
		},
		{
			name: "Services & Apps - Nginx",
			raw: ingestion.RawKEVItem{
				CVEID:         "CVE-TEST-4",
				VendorProject: "F5",
				Product:       "Nginx Web Server",
			},
			expected: model.CategoryServicesApps,
		},
		{
			name: "Other Category",
			raw: ingestion.RawKEVItem{
				CVEID:         "CVE-TEST-5",
				VendorProject: "Acme",
				Product:       "WidgetTool",
			},
			expected: model.CategoryOther,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vuln := ingestion.ClassifyRawKEV(tc.raw, now)
			if vuln.Category != tc.expected {
				t.Errorf("expected category %s, got %s", tc.expected, vuln.Category)
			}
		})
	}
}

func TestParser_VectorHeuristics(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name     string
		raw      ingestion.RawKEVItem
		expected model.Vector
	}{
		{
			name: "Remote Network Vector",
			raw: ingestion.RawKEVItem{
				CVEID:            "CVE-VEC-1",
				ShortDescription: "Allows remote attackers to send malicious HTTP packets.",
			},
			expected: model.VectorNetworkRemote,
		},
		{
			name: "Privilege Escalation Vector",
			raw: ingestion.RawKEVItem{
				CVEID:            "CVE-VEC-2",
				ShortDescription: "Allows a local user to obtain privilege escalation to root.",
			},
			expected: model.VectorLocalPrivesc,
		},
		{
			name: "Local Internal Vector",
			raw: ingestion.RawKEVItem{
				CVEID:            "CVE-VEC-3",
				ShortDescription: "An internal state inconsistency causes application crash.",
			},
			expected: model.VectorLocalInternal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vuln := ingestion.ClassifyRawKEV(tc.raw, now)
			if vuln.Vector != tc.expected {
				t.Errorf("expected vector %s, got %s", tc.expected, vuln.Vector)
			}
		})
	}
}

func TestParser_SeverityScoring(t *testing.T) {
	now := time.Now().UTC()

	// Critical when RCE
	rceItem := ingestion.ClassifyRawKEV(ingestion.RawKEVItem{
		VulnerabilityName: "Remote code execution flaw",
		ShortDescription:  "Arbitrary code execution via crafted input",
	}, now)
	if rceItem.Severity != model.SeverityCritical || rceItem.Score != 9.8 {
		t.Errorf("expected Critical 9.8, got %s %.1f", rceItem.Severity, rceItem.Score)
	}

	// Critical when unauthenticated
	unauthItem := ingestion.ClassifyRawKEV(ingestion.RawKEVItem{
		VulnerabilityName: "Bypass vulnerability",
		ShortDescription:  "Allows unauthenticated access to settings",
	}, now)
	if unauthItem.Severity != model.SeverityCritical || unauthItem.Score != 9.8 {
		t.Errorf("expected Critical 9.8, got %s %.1f", unauthItem.Severity, unauthItem.Score)
	}

	// Critical when UAF
	uafItem := ingestion.ClassifyRawKEV(ingestion.RawKEVItem{
		VulnerabilityName: "Use-after-free in graphics driver",
		ShortDescription:  "Memory corruption due to use after free",
	}, now)
	if uafItem.Severity != model.SeverityCritical || uafItem.Score != 9.8 {
		t.Errorf("expected Critical 9.8, got %s %.1f", uafItem.Severity, uafItem.Score)
	}

	// Default to High 7.5
	defaultItem := ingestion.ClassifyRawKEV(ingestion.RawKEVItem{
		VulnerabilityName: "Information disclosure",
		ShortDescription:  "Leaks configuration parameters",
	}, now)
	if defaultItem.Severity != model.SeverityHigh || defaultItem.Score != 7.5 {
		t.Errorf("expected High 7.5, got %s %.1f", defaultItem.Severity, defaultItem.Score)
	}
}

func TestParser_TaxonomyClassification(t *testing.T) {
	tests := []struct {
		name          string
		vendor        string
		product       string
		desc          string
		cweID         string
		wantEco       string
		wantTagSubstr string
	}{
		{
			name:          "Linux Kernel",
			vendor:        "Linux",
			product:       "Kernel",
			desc:          "Local privilege escalation in netfilter subsystem",
			cweID:         "CWE-787",
			wantEco:       model.EcosystemKernelOS,
			wantTagSubstr: "Linux Kernel",
		},
		{
			name:          "OpenSSL Shared Library",
			vendor:        "OpenSSL",
			product:       "OpenSSL",
			desc:          "Buffer overflow in X.509 certificate verification",
			cweID:         "CWE-120",
			wantEco:       model.EcosystemLibPkg,
			wantTagSubstr: "OpenSSL",
		},
		{
			name:          "Python Web Framework",
			vendor:        "Python Software Foundation",
			product:       "Python",
			desc:          "Arbitrary code execution via pickle deserialization",
			cweID:         "CWE-502",
			wantEco:       model.EcosystemRuntimeLang,
			wantTagSubstr: "Python",
		},
		{
			name:          "C/C++ Memory Corruption Inference",
			vendor:        "NativeTech",
			product:       "CoreDaemon",
			desc:          "Use-after-free allows remote code execution",
			cweID:         "CWE-416",
			wantEco:       model.EcosystemRuntimeLang,
			wantTagSubstr: "C/C++",
		},
		{
			name:          "Cisco Network Hardware",
			vendor:        "Cisco",
			product:       "IOS XE",
			desc:          "Authentication bypass in web UI",
			cweID:         "CWE-287",
			wantEco:       model.EcosystemNetworkHW,
			wantTagSubstr: "Network Infrastructure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eco, tags := ingestion.ClassifyTaxonomy(tt.vendor, tt.product, tt.desc, tt.cweID)
			if eco != tt.wantEco {
				t.Errorf("expected ecosystem %s, got %s", tt.wantEco, eco)
			}
			found := false
			for _, tag := range tags {
				if strings.Contains(tag, tt.wantTagSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected tag containing %q, got tags: %v", tt.wantTagSubstr, tags)
			}
		})
	}
}

