package styles

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	// Base Colors
	ColorBgDark     = lipgloss.Color("#0B0F17")
	ColorBgPanel    = lipgloss.Color("#111827")
	ColorBgSelected = lipgloss.Color("#1E293B")
	ColorBorder     = lipgloss.Color("#1E293B")
	ColorBorderHi   = lipgloss.Color("#06B6D4")

	// Foreground Colors
	ColorText       = lipgloss.Color("#E2E8F0")
	ColorTextMuted  = lipgloss.Color("#64748B")
	ColorTextDim    = lipgloss.Color("#475569")
	ColorHighlight  = lipgloss.Color("#38BDF8")

	// Accents & Telemetry
	ColorCyan    = lipgloss.Color("#06B6D4")
	ColorEmerald = lipgloss.Color("#10B981")
	ColorAmber   = lipgloss.Color("#F59E0B")
	ColorNeonRed = lipgloss.Color("#EF4444")
	ColorPurple  = lipgloss.Color("#8B5CF6")

	// Global Text Styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorCyan)

	MutedStyle = lipgloss.NewStyle().
			Foreground(ColorTextMuted)

	DimStyle = lipgloss.NewStyle().
			Foreground(ColorTextDim)

	BoldWhite = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF"))

	// HUD Badge Styles
	BadgeBase = lipgloss.NewStyle().
			Padding(0, 1).
			Bold(true)

	BadgeLive = BadgeBase.
			Background(lipgloss.Color("#064E3B")).
			Foreground(ColorEmerald)

	BadgeSyncing = BadgeBase.
			Background(lipgloss.Color("#451A03")).
			Foreground(ColorAmber)

	BadgeCritical = BadgeBase.
			Background(lipgloss.Color("#7F1D1D")).
			Foreground(lipgloss.Color("#FCA5A5"))

	BadgeHigh = BadgeBase.
			Background(lipgloss.Color("#78350F")).
			Foreground(lipgloss.Color("#FDE68A"))

	BadgeMedium = BadgeBase.
			Background(lipgloss.Color("#1E3A5F")).
			Foreground(lipgloss.Color("#93C5FD"))

	BadgeLow = BadgeBase.
			Background(lipgloss.Color("#064E3B")).
			Foreground(lipgloss.Color("#A7F3D0"))

	BadgeVector = BadgeBase.
			Background(lipgloss.Color("#3B0764")).
			Foreground(lipgloss.Color("#E9D5FF"))

	BadgeCategory = BadgeBase.
			Background(lipgloss.Color("#0F172A")).
			Foreground(ColorCyan)

	// Panel & Border Styles
	PanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(0, 1)

	ActivePanelStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(ColorBorderHi).
				Padding(0, 1)

	// Table Rows
	RowSelected = lipgloss.NewStyle().
			Background(ColorBgSelected).
			Foreground(lipgloss.Color("#FFFFFF")).
			Bold(true)

	RowNormal = lipgloss.NewStyle().
			Foreground(ColorText)

	// Modal
	ModalBox = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(ColorCyan).
			Background(ColorBgPanel).
			Padding(1, 2)
)
