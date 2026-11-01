package components

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/cicekhasann/cvegrid/internal/model"
	"github.com/cicekhasann/cvegrid/internal/ui/styles"
)

// TabItem represents a selectable category tab.
type TabItem struct {
	Index    int
	Key      string
	Title    string
	Category model.Category
}

var TabsList = []TabItem{
	{Index: 0, Key: "1", Title: "ALL", Category: model.CategoryAll},
	{Index: 1, Key: "2", Title: "KERNEL & OS", Category: model.CategoryKernelOS},
	{Index: 2, Key: "3", Title: "FIREWALL & NET", Category: model.CategoryFirewallNet},
	{Index: 3, Key: "4", Title: "MEMORY SAFETY", Category: model.CategoryMemorySafety},
	{Index: 4, Key: "5", Title: "SERVICES & APPS", Category: model.CategoryServicesApps},
}

// TabsModel renders the category filter tab-bar.
type TabsModel struct {
	ActiveIndex int
}

// NewTabsModel initializes the tabs component.
func NewTabsModel() TabsModel {
	return TabsModel{ActiveIndex: 0}
}

// ActiveCategory returns the category corresponding to the currently selected tab.
func (t TabsModel) ActiveCategory() model.Category {
	if t.ActiveIndex >= 0 && t.ActiveIndex < len(TabsList) {
		return TabsList[t.ActiveIndex].Category
	}
	return model.CategoryAll
}

// View renders the tab-bar.
func (t TabsModel) View(totalWidth int) string {
	var renderedTabs []string

	activeTabStyle := lipgloss.NewStyle().
		Bold(true).
		Background(styles.ColorCyan).
		Foreground(lipgloss.Color("#0B0F17")).
		Padding(0, 1)

	inactiveTabStyle := lipgloss.NewStyle().
		Background(styles.ColorBgPanel).
		Foreground(styles.ColorTextMuted).
		Padding(0, 1)

	for i, tab := range TabsList {
		label := fmt.Sprintf("[%s: %s]", tab.Key, tab.Title)
		if i == t.ActiveIndex {
			renderedTabs = append(renderedTabs, activeTabStyle.Render(label))
		} else {
			renderedTabs = append(renderedTabs, inactiveTabStyle.Render(label))
		}
	}

	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
	return lipgloss.NewStyle().
		Padding(0, 1, 1, 1).
		Render(tabBar)
}
