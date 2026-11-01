package ui

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cicekhasann/cvegrid/internal/database"
	"github.com/cicekhasann/cvegrid/internal/ingestion"
	"github.com/cicekhasann/cvegrid/internal/model"
	"github.com/cicekhasann/cvegrid/internal/ui/components"
	"github.com/cicekhasann/cvegrid/internal/ui/keys"
	"github.com/cicekhasann/cvegrid/internal/ui/styles"
)

// ViewMode represents active interaction mode.
type ViewMode int

const (
	ModeNormal ViewMode = iota
	ModeSearch
	ModeModal
)

// DataLoadedMsg delivers fetched data to the UI event loop.
type DataLoadedMsg struct {
	Items []model.Vulnerability
	Stats model.Stats
	Err   error
}

// AppModel represents the root Bubbletea application state machine.
type AppModel struct {
	repo         *database.Repository
	sync         *ingestion.Synchronizer
	keys         keys.KeyMap
	mode         ViewMode
	width        int
	height       int
	header       components.HeaderModel
	tabs         components.TabsModel
	table        components.StreamTableModel
	preview      components.PreviewPanelModel
	modal        components.DossierModalModel
	searchInput  textinput.Model
	isSearching  bool
	statusMsg    string
	syncOngoing  bool
}

// NewAppModel initializes the root TUI model.
func NewAppModel(repo *database.Repository, syncer *ingestion.Synchronizer) AppModel {
	ti := textinput.New()
	ti.Placeholder = "Search CVE ID, vendor, or product (press Enter to confirm, Esc to clear)..."
	ti.CharLimit = 64
	ti.Width = 60

	return AppModel{
		repo:        repo,
		sync:        syncer,
		keys:        keys.DefaultKeyMap(),
		mode:        ModeNormal,
		header:      components.NewHeaderModel(),
		tabs:        components.NewTabsModel(),
		table:       components.NewStreamTableModel(),
		preview:     components.NewPreviewPanelModel(),
		modal:       components.NewDossierModalModel(),
		searchInput: ti,
	}
}

// Init triggers initial data load and background sync if needed.
func (a AppModel) Init() tea.Cmd {
	cmds := []tea.Cmd{
		a.loadDataCmd(),
		a.header.Spinner.Tick,
	}

	if a.repo != nil && a.repo.Count() == 0 && a.sync != nil {
		cmds = append(cmds,
			func() tea.Msg {
				return ingestion.SyncStartedMsg{}
			},
			a.sync.SyncCmd(),
		)
	}

	return tea.Batch(cmds...)
}

// loadDataCmd retrieves threat records and stats asynchronously.
func (a AppModel) loadDataCmd() tea.Cmd {
	category := a.tabs.ActiveCategory()
	query := a.searchInput.Value()

	return func() tea.Msg {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		items, err := a.repo.GetVulnerabilities(ctx, database.FilterOptions{
			Category:    category,
			SearchQuery: query,
		})
		if err != nil {
			return DataLoadedMsg{Err: err}
		}

		stats, err := a.repo.GetStats(ctx)
		if err != nil {
			return DataLoadedMsg{Err: err}
		}

		return DataLoadedMsg{
			Items: items,
			Stats: stats,
		}
	}
}

// Update processes Bubbletea events and state transitions.
func (a AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		a.header.Width = msg.Width
		a.modal.TotalWidth = msg.Width
		a.modal.TotalHeight = msg.Height
		a.recalculateLayout()
		return a, nil

	case spinner.TickMsg:
		if a.syncOngoing {
			var cmd tea.Cmd
			a.header.Spinner, cmd = a.header.Spinner.Update(msg)
			cmds = append(cmds, cmd)
		}

	case ingestion.SyncStartedMsg:
		a.syncOngoing = true
		a.header.IsSync = true
		cmds = append(cmds, a.header.Spinner.Tick)

	case ingestion.SyncFinishedMsg:
		a.syncOngoing = false
		a.header.IsSync = false
		if msg.Err != nil {
			a.statusMsg = fmt.Sprintf("Sync failed: %v", msg.Err)
		} else {
			a.statusMsg = fmt.Sprintf("Successfully synced %d records in %v", msg.Count, msg.Duration.Round(10*1000*1000))
		}
		cmds = append(cmds, a.loadDataCmd())

	case DataLoadedMsg:
		if msg.Err == nil {
			a.table.SetItems(msg.Items)
			a.header.Stats = msg.Stats
			a.preview.Item = a.table.SelectedRow()
		}

	case tea.KeyMsg:
		// Modal interaction mode
		if a.mode == ModeModal {
			switch msg.String() {
			case "esc", "q":
				a.mode = ModeNormal
				return a, nil
			case "up", "k":
				a.modal.ScrollUp()
				return a, nil
			case "down", "j":
				a.modal.ScrollDown()
				return a, nil
			case "o":
				if a.modal.Item != nil {
					openBrowser(a.modal.Item.CVEID)
				}
				return a, nil
			}
			return a, nil
		}

		// Search input interaction mode
		if a.mode == ModeSearch {
			switch msg.String() {
			case "esc":
				a.mode = ModeNormal
				a.searchInput.Blur()
				a.searchInput.SetValue("")
				cmds = append(cmds, a.loadDataCmd())
				return a, tea.Batch(cmds...)
			case "enter":
				a.mode = ModeNormal
				a.searchInput.Blur()
				cmds = append(cmds, a.loadDataCmd())
				return a, tea.Batch(cmds...)
			default:
				var cmd tea.Cmd
				a.searchInput, cmd = a.searchInput.Update(msg)
				cmds = append(cmds, cmd, a.loadDataCmd())
				return a, tea.Batch(cmds...)
			}
		}

		// Normal interaction mode
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit

		case "up", "k":
			a.table.MoveUp()
			a.preview.Item = a.table.SelectedRow()

		case "down", "j":
			a.table.MoveDown()
			a.preview.Item = a.table.SelectedRow()

		case "pgup", "b":
			a.table.PageUp()
			a.preview.Item = a.table.SelectedRow()

		case "pgdown", "f":
			a.table.PageDown()
			a.preview.Item = a.table.SelectedRow()

		case "g", "home":
			a.table.GoToTop()
			a.preview.Item = a.table.SelectedRow()

		case "G", "end":
			a.table.GoToBottom()
			a.preview.Item = a.table.SelectedRow()

		case "1", "2", "3", "4", "5":
			idx := int(msg.String()[0] - '1')
			a.tabs.ActiveIndex = idx
			cmds = append(cmds, a.loadDataCmd())

		case "/":
			a.mode = ModeSearch
			a.searchInput.Focus()
			return a, textinput.Blink

		case "enter":
			if row := a.table.SelectedRow(); row != nil {
				a.modal.SetItem(row)
				a.mode = ModeModal
			}

		case "o":
			if row := a.table.SelectedRow(); row != nil {
				openBrowser(row.CVEID)
			}

		case "r":
			if !a.syncOngoing && a.sync != nil {
				a.syncOngoing = true
				a.header.IsSync = true
				cmds = append(cmds, a.header.Spinner.Tick, a.sync.SyncCmd())
			}
		}
	}

	return a, tea.Batch(cmds...)
}

func (a *AppModel) recalculateLayout() {
	if a.width < 90 || a.height < 20 {
		return
	}

	// Layout proportions: Left Panel 52%, Right Panel 48%
	totalAvailableWidth := a.width - 2
	leftWidth := int(float64(totalAvailableWidth) * 0.52)
	rightWidth := totalAvailableWidth - leftWidth

	// Header is ~3 lines, tabs ~2 lines, status/search ~2 lines
	contentHeight := a.height - 8
	if contentHeight < 8 {
		contentHeight = 8
	}

	a.table.Width = leftWidth
	a.table.Height = contentHeight

	a.preview.Width = rightWidth
	a.preview.Height = contentHeight
}

// View renders the terminal user interface.
func (a AppModel) View() string {
	// Terminal resize guard: Graceful handling for terminals smaller than 90x20
	if a.width < 90 || a.height < 20 {
		warnBox := lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(styles.ColorNeonRed).
			Padding(1, 2).
			Align(lipgloss.Center).
			Render(fmt.Sprintf(
				"%s\n\nTerminal geometry too small: %dx%d\nRequired minimum: 90x20\n\nPlease expand your terminal window.",
				styles.BadgeCritical.Render("TERMINAL WINDOW TOO SMALL"),
				a.width, a.height,
			))

		return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center, warnBox)
	}

	if a.mode == ModeModal {
		return a.modal.View()
	}

	headerView := a.header.View()
	tabsView := a.tabs.View(a.width)

	workstation := lipgloss.JoinHorizontal(lipgloss.Top,
		a.table.View(),
		a.preview.View(),
	)

	// Bottom bar: Search prompt or status bar
	var bottomBar string
	if a.mode == ModeSearch {
		promptStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(styles.ColorCyan).
			Render("SEARCH [/]: ")
		bottomBar = lipgloss.JoinHorizontal(lipgloss.Left, promptStyle, a.searchInput.View())
	} else {
		searchQuery := a.searchInput.Value()
		var filterIndicator string
		if strings.TrimSpace(searchQuery) != "" {
			filterIndicator = styles.BadgeVector.Render(fmt.Sprintf("FILTER: %q", searchQuery)) + "  "
		}

		status := a.statusMsg
		if status == "" {
			status = styles.DimStyle.Render("[j/k] Nav  [1-5] Category  [/] Search  [Enter] Dossier  [o] NIST  [r] Sync  [q] Quit")
		} else {
			status = styles.MutedStyle.Render(status)
		}
		bottomBar = lipgloss.JoinHorizontal(lipgloss.Left, filterIndicator, status)
	}

	bottomBarContainer := lipgloss.NewStyle().
		Padding(0, 1).
		Render(bottomBar)

	return lipgloss.JoinVertical(lipgloss.Left,
		headerView,
		tabsView,
		workstation,
		bottomBarContainer,
	)
}

func openBrowser(cveID string) {
	url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}

	_ = cmd.Start()
}
