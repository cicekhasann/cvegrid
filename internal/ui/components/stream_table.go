package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/cicekhasann/cvegrid/internal/model"
	"github.com/cicekhasann/cvegrid/internal/ui/styles"
)

// StreamTableModel handles rendering and navigation for the threat feed table.
type StreamTableModel struct {
	Items  []model.Vulnerability
	Cursor int
	Offset int
	Width  int
	Height int
}

// NewStreamTableModel initializes the table model.
func NewStreamTableModel() StreamTableModel {
	return StreamTableModel{
		Items:  make([]model.Vulnerability, 0),
		Cursor: 0,
		Offset: 0,
	}
}

// SetItems updates the dataset and adjusts cursor if necessary.
func (m *StreamTableModel) SetItems(items []model.Vulnerability) {
	m.Items = items
	if m.Cursor >= len(items) {
		m.Cursor = len(items) - 1
	}
	if m.Cursor < 0 {
		m.Cursor = 0
	}
	m.adjustOffset()
}

// SelectedRow returns a pointer to the active vulnerability, or nil if empty.
func (m StreamTableModel) SelectedRow() *model.Vulnerability {
	if len(m.Items) == 0 || m.Cursor < 0 || m.Cursor >= len(m.Items) {
		return nil
	}
	return &m.Items[m.Cursor]
}

// MoveUp shifts selection up by one.
func (m *StreamTableModel) MoveUp() {
	if m.Cursor > 0 {
		m.Cursor--
		m.adjustOffset()
	}
}

// MoveDown shifts selection down by one.
func (m *StreamTableModel) MoveDown() {
	if m.Cursor < len(m.Items)-1 {
		m.Cursor++
		m.adjustOffset()
	}
}

// PageUp jumps up by visible page size.
func (m *StreamTableModel) PageUp() {
	pageSize := m.visibleRows()
	m.Cursor -= pageSize
	if m.Cursor < 0 {
		m.Cursor = 0
	}
	m.adjustOffset()
}

// PageDown jumps down by visible page size.
func (m *StreamTableModel) PageDown() {
	pageSize := m.visibleRows()
	m.Cursor += pageSize
	if m.Cursor >= len(m.Items) {
		m.Cursor = len(m.Items) - 1
	}
	if m.Cursor < 0 {
		m.Cursor = 0
	}
	m.adjustOffset()
}

// GoToTop jumps to the first row.
func (m *StreamTableModel) GoToTop() {
	m.Cursor = 0
	m.Offset = 0
}

// GoToBottom jumps to the last row.
func (m *StreamTableModel) GoToBottom() {
	if len(m.Items) > 0 {
		m.Cursor = len(m.Items) - 1
		m.adjustOffset()
	}
}

func (m *StreamTableModel) visibleRows() int {
	// Table container height minus header, divider, and padding
	h := m.Height - 4
	if h < 1 {
		return 1
	}
	return h
}

func (m *StreamTableModel) adjustOffset() {
	visible := m.visibleRows()
	if m.Cursor < m.Offset {
		m.Offset = m.Cursor
	} else if m.Cursor >= m.Offset+visible {
		m.Offset = m.Cursor - visible + 1
	}
	if m.Offset < 0 {
		m.Offset = 0
	}
}

func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-1]) + "…"
}

// View renders the left threat stream table.
func (m StreamTableModel) View() string {
	contentWidth := m.Width - 4
	if contentWidth < 40 {
		contentWidth = 40
	}

	dateWidth := 10
	cveWidth := 15
	sevWidth := 11
	targetWidth := contentWidth - (dateWidth + cveWidth + sevWidth + 6)
	if targetWidth < 12 {
		targetWidth = 12
	}

	// Table Header
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(styles.ColorHighlight)

	colDateHdr := fmt.Sprintf("%-10s", "DATE")
	colCVEHdr := fmt.Sprintf("%-15s", "CVE ID")
	colTargetHdr := fmt.Sprintf("%-*s", targetWidth, truncate("TARGET (VENDOR + PRODUCT)", targetWidth))
	colSevHdr := fmt.Sprintf("%11s", "SEVERITY")

	tableHeader := headerStyle.Render(fmt.Sprintf("%s  %s  %s  %s", colDateHdr, colCVEHdr, colTargetHdr, colSevHdr))
	divider := styles.DimStyle.Render(strings.Repeat("─", contentWidth))

	visible := m.visibleRows()
	var rows []string

	if len(m.Items) == 0 {
		emptyMsg := styles.MutedStyle.Render("No threat records found matching criteria.")
		rows = append(rows, emptyMsg)
	} else {
		endIdx := m.Offset + visible
		if endIdx > len(m.Items) {
			endIdx = len(m.Items)
		}

		for i := m.Offset; i < endIdx; i++ {
			item := m.Items[i]
			targetStr := item.Vendor
			if item.Product != "" {
				targetStr = fmt.Sprintf("%s / %s", item.Vendor, item.Product)
			}
			targetStr = truncate(targetStr, targetWidth)

			colDate := fmt.Sprintf("%-10s", item.DateAdded)
			colCVE := fmt.Sprintf("%-15s", item.CVEID)
			colTarget := fmt.Sprintf("%-*s", targetWidth, targetStr)

			var sevBadge string
			switch item.Severity {
			case model.SeverityCritical:
				sevBadge = styles.BadgeCritical.Render(fmt.Sprintf("CRIT %.1f", item.Score))
			case model.SeverityHigh:
				sevBadge = styles.BadgeHigh.Render(fmt.Sprintf("HIGH %.1f", item.Score))
			case model.SeverityMedium:
				sevBadge = styles.BadgeMedium.Render(fmt.Sprintf("MED  %.1f", item.Score))
			default:
				sevBadge = styles.BadgeLow.Render(fmt.Sprintf("LOW  %.1f", item.Score))
			}

			rowContent := fmt.Sprintf("%s  %s  %s  %s", colDate, colCVE, colTarget, sevBadge)
			if i == m.Cursor {
				selectedStyle := lipgloss.NewStyle().
					Width(contentWidth).
					Background(styles.ColorBgSelected).
					Bold(true)
				rows = append(rows, selectedStyle.Render(rowContent))
			} else {
				rowStyle := lipgloss.NewStyle().
					Width(contentWidth).
					Foreground(styles.ColorText)
				rows = append(rows, rowStyle.Render(rowContent))
			}
		}
	}

	for len(rows) < visible {
		rows = append(rows, "")
	}

	body := lipgloss.JoinVertical(lipgloss.Left, rows...)
	fullContent := lipgloss.JoinVertical(lipgloss.Left, tableHeader, divider, body)

	panel := styles.ActivePanelStyle.
		Width(m.Width).
		Height(m.Height).
		Render(fullContent)

	return panel
}
