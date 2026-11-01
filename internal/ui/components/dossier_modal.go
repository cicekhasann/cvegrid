package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/cicekhasann/cvegrid/internal/model"
	"github.com/cicekhasann/cvegrid/internal/ui/styles"
)

// DossierModalModel handles the full-screen centered deep inspection modal dialog.
type DossierModalModel struct {
	Item        *model.Vulnerability
	ScrollIndex int
	TotalWidth  int
	TotalHeight int
}

// NewDossierModalModel initializes the modal.
func NewDossierModalModel() DossierModalModel {
	return DossierModalModel{}
}

// SetItem sets the vulnerability to inspect and resets scroll.
func (d *DossierModalModel) SetItem(item *model.Vulnerability) {
	d.Item = item
	d.ScrollIndex = 0
}

// ScrollUp scrolls modal content up.
func (d *DossierModalModel) ScrollUp() {
	if d.ScrollIndex > 0 {
		d.ScrollIndex--
	}
}

// ScrollDown scrolls modal content down.
func (d *DossierModalModel) ScrollDown() {
	d.ScrollIndex++
}

// View renders the centered double-border modal overlay.
func (d DossierModalModel) View() string {
	if d.Item == nil {
		return ""
	}

	item := d.Item

	modalWidth := int(float64(d.TotalWidth) * 0.88)
	if modalWidth < 60 {
		modalWidth = 60
	}
	if modalWidth > 120 {
		modalWidth = 120
	}

	modalHeight := int(float64(d.TotalHeight) * 0.88)
	if modalHeight < 15 {
		modalHeight = 15
	}

	innerWidth := modalWidth - 6
	if innerWidth < 20 {
		innerWidth = 20
	}

	// Modal Header
	titleStr := styles.TitleStyle.Render("╔═ [ DOSSIER DEEP INSPECTION & THREAT KILL CHAIN ] ═══════════════════")
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

	headerLine := lipgloss.JoinHorizontal(lipgloss.Center, cveTitle, "   ", sevBadge)
	div := styles.DimStyle.Render(strings.Repeat("═", innerWidth))

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

	instantBadgesRow := lipgloss.JoinHorizontal(lipgloss.Top, urgencyBadge, "   ", exploitBadge, "   ", actionBadge)

	// Ransomware Alert Callout
	var ransomwareBanner string
	if item.RansomwareCampaign == 1 {
		ransomwareBanner = styles.BadgeCritical.Render("🚨 THREAT INTEL ALERT: KNOWN EXPLOITATION BY RANSOMWARE OPERATORS")
	}

	// 1. Executive Summary (TL;DR) - At the very top
	tldrHdr := styles.TitleStyle.Render("EXECUTIVE SUMMARY (TL;DR):")
	summaryText := item.ExecutiveSummary
	if summaryText == "" {
		summaryText = item.Description
	}
	tldrTxt := lipgloss.NewStyle().Width(innerWidth).Foreground(styles.ColorText).Bold(true).Render(summaryText)

	// 2. What should you do right now? (Action Box)
	actionHdr := styles.BadgeLive.Render("WHAT SHOULD YOU DO RIGHT NOW?")
	actionContent := fmt.Sprintf("• ACTION: %s\n• MITIGATION GUIDANCE: %s", item.RequiredAction, item.RemediationNotes)
	if item.DueDate != "" {
		actionContent += fmt.Sprintf("\n• MANDATORY DUE DATE: %s", item.DueDate)
	}
	actionTxt := lipgloss.NewStyle().Width(innerWidth).Foreground(lipgloss.Color("#A7F3D0")).Render(actionContent)

	// 3. Recommended Threat Intelligence & Deep Reads
	readsHdr := styles.TitleStyle.Render("RECOMMENDED THREAT INTELLIGENCE & DEEP READS:")
	var readsList []string
	if len(item.Articles) > 0 {
		for _, art := range item.Articles {
			readsList = append(readsList, fmt.Sprintf("%s %s\n  ↳ %s",
				styles.DimStyle.Render(art.Badge+":"),
				styles.BoldWhite.Render(art.Title),
				styles.MutedStyle.Render(art.URL),
			))
		}
	} else {
		readsList = append(readsList, fmt.Sprintf("• NIST NVD: https://nvd.nist.gov/vuln/detail/%s\n• CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog", item.CVEID))
	}
	readsTxt := lipgloss.NewStyle().Width(innerWidth).Render(strings.Join(readsList, "\n"))

	// 4. Pro Technical Telemetry (Collapsible / Technical Section)
	proDivider := styles.DimStyle.Render(strings.Repeat("─", innerWidth))
	proHdr := styles.TitleStyle.Render("[ PRO INSPECTOR: DEEP TECHNICAL TELEMETRY ]")

	metaVendor := fmt.Sprintf("%s: %s", styles.DimStyle.Render("VENDOR"), styles.BoldWhite.Render(item.Vendor))
	metaProduct := fmt.Sprintf("%s: %s", styles.DimStyle.Render("PRODUCT"), styles.BoldWhite.Render(item.Product))
	metaDate := fmt.Sprintf("%s: %s", styles.DimStyle.Render("DATE ADDED"), styles.MutedStyle.Render(item.DateAdded))
	metaSource := fmt.Sprintf("%s: %s", styles.DimStyle.Render("SOURCE"), styles.MutedStyle.Render(item.Source))

	metaCat := styles.BadgeCategory.Render("CATEGORY: " + string(item.Category))
	metaVec := styles.BadgeVector.Render("ATTACK VECTOR: " + string(item.Vector))
	metaCWE := styles.BadgeMedium.Render("CWE: " + item.CWEID)
	metaEPSS := styles.BadgeHigh.Render(fmt.Sprintf("EPSS: %.2f%% (%dth Pct)", item.EPSSScore*100, int(item.EPSSPercentile*100)))

	metaGridRow1 := lipgloss.JoinHorizontal(lipgloss.Top, metaVendor, "   |   ", metaProduct)
	metaGridRow2 := lipgloss.JoinHorizontal(lipgloss.Top, metaDate, "   |   ", metaSource)
	metaGridRow3 := lipgloss.JoinHorizontal(lipgloss.Top, metaCat, "   ", metaVec, "   ", metaCWE, "   ", metaEPSS)

	var cweExplanation string
	if item.CWEDescription != "" {
		cweExplanation = fmt.Sprintf("%s %s", styles.DimStyle.Render("CWE DEFINITION:"), styles.MutedStyle.Render(item.CWEDescription))
	}

	var cvssVectorRow string
	if item.CVSSVector != "" {
		cvssVectorRow = fmt.Sprintf("%s %s", styles.DimStyle.Render("CVSS v3.1 VECTOR:"), styles.MutedStyle.Render(item.CVSSVector))
	}

	// Raw Description
	descHdr := styles.DimStyle.Render("RAW TECHNICAL DESCRIPTION:")
	descTxt := lipgloss.NewStyle().Width(innerWidth).Foreground(styles.ColorTextDim).Render(item.Description)

	// Modal Footer / Controls
	footerDivider := styles.DimStyle.Render(strings.Repeat("═", innerWidth))
	controls := styles.MutedStyle.Render("[Esc/q] Close Modal   [o] Open NIST Bulletin in Browser   [↑/k] [↓/j] Scroll")

	sections := []string{
		titleStr,
		"",
		headerLine,
		instantBadgesRow,
		div,
	}

	if ransomwareBanner != "" {
		sections = append(sections, ransomwareBanner, "")
	}

	sections = append(sections,
		tldrHdr,
		tldrTxt,
		"",
		actionHdr,
		actionTxt,
		"",
		readsHdr,
		readsTxt,
		"",
		proDivider,
		proHdr,
		metaGridRow1,
		metaGridRow2,
		metaGridRow3,
	)

	if cweExplanation != "" {
		sections = append(sections, cweExplanation)
	}

	if cvssVectorRow != "" {
		sections = append(sections, cvssVectorRow)
	}

	sections = append(sections,
		"",
		descHdr,
		descTxt,
		"",
		footerDivider,
		controls,
	)

	content := lipgloss.JoinVertical(lipgloss.Left, sections...)

	modalCard := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(styles.ColorCyan).
		Background(styles.ColorBgPanel).
		Padding(1, 2).
		Width(modalWidth).
		MaxHeight(modalHeight).
		Render(content)

	return lipgloss.Place(
		d.TotalWidth,
		d.TotalHeight,
		lipgloss.Center,
		lipgloss.Center,
		modalCard,
	)
}
