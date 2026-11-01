package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/cicekhasann/cvegrid/internal/model"
	"github.com/cicekhasann/cvegrid/internal/ui/styles"
)

// PreviewPanelModel renders instantaneous metadata of the active row.
type PreviewPanelModel struct {
	Item   *model.Vulnerability
	Width  int
	Height int
}

// NewPreviewPanelModel initializes the preview panel.
func NewPreviewPanelModel() PreviewPanelModel {
	return PreviewPanelModel{}
}

// View renders the right-hand preview panel.
func (p PreviewPanelModel) View() string {
	contentWidth := p.Width - 4
	if contentWidth < 30 {
		contentWidth = 30
	}

	if p.Item == nil {
		emptyNotice := lipgloss.NewStyle().
			Width(contentWidth).
			Height(p.Height - 2).
			Align(lipgloss.Center, lipgloss.Center).
			Render(styles.MutedStyle.Render("No active vulnerability selected."))

		return styles.PanelStyle.
			Width(p.Width).
			Height(p.Height).
			Render(emptyNotice)
	}

	item := p.Item

	// Header row: CVE ID and Severity Badge
	cveTitle := styles.BoldWhite.Render(item.CVEID)
	var sevBadge string
	switch item.Severity {
	case model.SeverityCritical:
		sevBadge = styles.BadgeCritical.Render(fmt.Sprintf("CRITICAL %.1f", item.Score))
	case model.SeverityHigh:
		sevBadge = styles.BadgeHigh.Render(fmt.Sprintf("HIGH %.1f", item.Score))
	case model.SeverityMedium:
		sevBadge = styles.BadgeMedium.Render(fmt.Sprintf("MEDIUM %.1f", item.Score))
	default:
		sevBadge = styles.BadgeLow.Render(fmt.Sprintf("LOW %.1f", item.Score))
	}

	headerRow := lipgloss.JoinHorizontal(lipgloss.Center, cveTitle, "  ", sevBadge)
	divider := styles.DimStyle.Render(strings.Repeat("─", contentWidth))

	// 3 Instant Badges
	urgencyText := item.Urgency
	if urgencyText == "" {
		urgencyText = "SCHEDULE MAINTENANCE"
	}
	var urgencyBadge string
	if urgencyText == "IMMEDIATE ACTION REQUIRED" {
		urgencyBadge = styles.BadgeCritical.Render("URGENCY: " + urgencyText)
	} else {
		urgencyBadge = styles.BadgeHigh.Render("URGENCY: " + urgencyText)
	}

	exploitText := item.ExploitStatus
	if exploitText == "" {
		exploitText = "ACTIVE IN WILD"
	}
	exploitBadge := styles.BadgeCritical.Render("🔥 " + exploitText)

	actionText := item.ActionSummary
	if actionText == "" {
		actionText = "APPLY VENDOR MITIGATION"
	}
	actionBadge := styles.BadgeLive.Render("⚡ " + actionText)

	instantBadgesRow := lipgloss.JoinHorizontal(lipgloss.Top, urgencyBadge, " ", exploitBadge, " ", actionBadge)

	// Ransomware Warning Banner
	var ransomwareBanner string
	if item.RansomwareCampaign == 1 {
		ransomwareBanner = styles.BadgeCritical.Render("🚨 RANSOMWARE GANGS: ACTIVE EXPLOITATION DETECTED")
	}

	// 1. Executive Summary (TL;DR) - Placed at the very top
	tldrHeader := styles.TitleStyle.Render("EXECUTIVE SUMMARY (TL;DR)")
	summaryText := item.ExecutiveSummary
	if summaryText == "" {
		summaryText = item.Description
	}
	wrappedTLDR := lipgloss.NewStyle().
		Width(contentWidth).
		Foreground(styles.ColorText).
		Bold(true).
		Render(summaryText)

	// 2. Recommended Threat Intelligence & Deep Reads
	readsHeader := styles.TitleStyle.Render("RECOMMENDED THREAT INTEL & DEEP READS")
	var readsList []string
	if len(item.Articles) > 0 {
		for _, art := range item.Articles {
			readsList = append(readsList, fmt.Sprintf("%s %s\n  %s",
				styles.DimStyle.Render(art.Badge+":"),
				styles.BoldWhite.Render(art.Title),
				styles.MutedStyle.Render(art.URL),
			))
		}
	} else {
		readsList = append(readsList, fmt.Sprintf("• %s: https://nvd.nist.gov/vuln/detail/%s", styles.MutedStyle.Render("NIST NVD Bulletin"), item.CVEID))
	}
	wrappedReads := lipgloss.NewStyle().Width(contentWidth).Render(strings.Join(readsList, "\n"))

	// 3. Mitigation / Mandatory Action Box
	var mitigationBlock string
	if item.RequiredAction != "" {
		mitHeader := styles.BadgeLive.Render("WHAT SHOULD YOU DO RIGHT NOW?")
		mitContent := lipgloss.NewStyle().
			Width(contentWidth).
			Foreground(lipgloss.Color("#A7F3D0")).
			Render(fmt.Sprintf("• ACTION: %s\n• REMEDIATION: %s", item.RequiredAction, item.RemediationNotes))
		mitigationBlock = lipgloss.JoinVertical(lipgloss.Left, mitHeader, mitContent)
	}

	// 4. Pro Technical Telemetry (Target, CWE, EPSS, Vectors)
	targetLabel := styles.DimStyle.Render("TARGET: ")
	targetVal := styles.BoldWhite.Render(fmt.Sprintf("%s (%s)", item.Product, item.Vendor))
	targetRow := lipgloss.JoinHorizontal(lipgloss.Top, targetLabel, targetVal)

	vecBadge := styles.BadgeVector.Render(string(item.Vector))
	catBadge := styles.BadgeCategory.Render(string(item.Category))
	cweBadge := styles.BadgeMedium.Render(item.CWEID)
	epssBadge := styles.BadgeHigh.Render(fmt.Sprintf("EPSS %.1f%%", item.EPSSScore*100))
	telemetryRow := lipgloss.JoinHorizontal(lipgloss.Top, vecBadge, "  ", catBadge, "  ", cweBadge, "  ", epssBadge)

	var cvssVectorRow string
	if item.CVSSVector != "" {
		cvssVectorRow = fmt.Sprintf("%s %s", styles.DimStyle.Render("CVSS v3.1:"), styles.MutedStyle.Render(item.CVSSVector))
	}

	// Hotkey hints bar at the bottom
	hints := styles.MutedStyle.Render("[Enter] Deep Dossier   [o] Open NIST   [/] Search   [r] Sync")

	sections := []string{
		headerRow,
		divider,
		instantBadgesRow,
	}

	if ransomwareBanner != "" {
		sections = append(sections, "", ransomwareBanner)
	}

	sections = append(sections,
		"",
		tldrHeader,
		wrappedTLDR,
		"",
		readsHeader,
		wrappedReads,
	)

	if mitigationBlock != "" {
		sections = append(sections, "", mitigationBlock)
	}

	sections = append(sections,
		"",
		divider,
		targetRow,
		telemetryRow,
	)

	if cvssVectorRow != "" {
		sections = append(sections, cvssVectorRow)
	}

	sections = append(sections, "", divider, hints)

	content := lipgloss.JoinVertical(lipgloss.Left, sections...)

	return styles.PanelStyle.
		Width(p.Width).
		Height(p.Height).
		Render(content)
}
