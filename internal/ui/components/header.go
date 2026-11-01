package components

import (
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"
	"github.com/cicekhasann/cvegrid/internal/model"
	"github.com/cicekhasann/cvegrid/internal/ui/styles"
)

// HeaderModel renders top HUD telemetry badges.
type HeaderModel struct {
	Stats    model.Stats
	IsSync   bool
	Spinner  spinner.Model
	Width    int
}

// NewHeaderModel creates an initialized HeaderModel.
func NewHeaderModel() HeaderModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(styles.ColorAmber)
	return HeaderModel{
		Spinner: s,
	}
}

// View renders the HUD telemetry banner.
func (h HeaderModel) View() string {
	appTitle := styles.TitleStyle.Render("⚡ CVEGRID")
	versionBadge := styles.DimStyle.Render("v1.0.0-PROD")

	totalBadge := styles.PanelStyle.Render(fmt.Sprintf("%s %s",
		styles.DimStyle.Render("TOTAL:"),
		styles.BoldWhite.Render(fmt.Sprintf("%d", h.Stats.TotalRecords)),
	))

	critBadge := styles.BadgeCritical.Render(fmt.Sprintf("CRIT (9.0+): %d", h.Stats.CriticalCount))
	highBadge := styles.BadgeHigh.Render(fmt.Sprintf("HIGH: %d", h.Stats.HighCount))

	var feedBadge string
	if h.IsSync {
		feedBadge = styles.BadgeSyncing.Render(fmt.Sprintf("%s SYNCING FEED...", h.Spinner.View()))
	} else {
		feedBadge = styles.BadgeLive.Render("● FEED: CISA KEV (LIVE)")
	}

	lastSyncBadge := styles.MutedStyle.Render(fmt.Sprintf("SYNC: %s", h.Stats.LastSync))

	leftHUD := lipgloss.JoinHorizontal(lipgloss.Center,
		appTitle, " ", versionBadge, "  ",
		totalBadge, " ",
		critBadge, " ",
		highBadge,
	)

	rightHUD := lipgloss.JoinHorizontal(lipgloss.Center,
		feedBadge, "  ",
		lastSyncBadge,
	)

	// Calculate space between left and right HUD elements
	leftLen := lipgloss.Width(leftHUD)
	rightLen := lipgloss.Width(rightHUD)
	gap := h.Width - leftLen - rightLen - 2
	if gap < 2 {
		gap = 2
	}

	spacer := lipgloss.NewStyle().Width(gap).Render("")
	hudRow := lipgloss.JoinHorizontal(lipgloss.Center, leftHUD, spacer, rightHUD)

	return lipgloss.NewStyle().
		Width(h.Width).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(styles.ColorBorder).
		Padding(0, 1, 1, 1).
		Render(hudRow)
}
