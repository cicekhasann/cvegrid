package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cicekhasann/cvegrid/internal/config"
	"github.com/cicekhasann/cvegrid/internal/daemon"
	"github.com/cicekhasann/cvegrid/internal/database"
	"github.com/cicekhasann/cvegrid/internal/ingestion"
	"github.com/cicekhasann/cvegrid/internal/locale"
	"github.com/cicekhasann/cvegrid/internal/ui"
	"github.com/cicekhasann/cvegrid/internal/web"
	"github.com/mattn/go-isatty"
)

const (
	Version = "1.2.0"
)

func main() {
	msg := locale.GetMessages()

	// 1. Intercept internal daemon worker process
	if len(os.Args) > 1 && os.Args[1] == "__daemon_worker" {
		runDaemonWorker()
		return
	}

	// 2. Intercept "web" subcommands: start, stop, status
	if len(os.Args) > 1 && os.Args[1] == "web" {
		handleWebSubcommand(os.Args[2:], msg)
		return
	}

	// 3. Standard CLI flags
	var (
		flagTUI     bool
		flagWeb     bool
		flagDaemon  bool
		flagPort    int
		flagSync    bool
		flagDB      string
		flagFeed    string
		flagVersion bool
	)

	flag.BoolVar(&flagTUI, "tui", false, "Launch the Bubbletea Terminal TUI")
	flag.BoolVar(&flagTUI, "t", false, "Launch the Bubbletea Terminal TUI (shorthand)")
	flag.BoolVar(&flagWeb, "web", false, "Launch the embedded Web Threat Console")
	flag.BoolVar(&flagWeb, "w", false, "Launch the embedded Web Threat Console (shorthand)")
	flag.BoolVar(&flagDaemon, "daemon", false, "Run web dashboard as background daemon")
	flag.BoolVar(&flagDaemon, "d", false, "Run web dashboard as background daemon (shorthand)")
	flag.IntVar(&flagPort, "port", web.DefaultPort, "HTTP port for web dashboard")
	flag.IntVar(&flagPort, "p", web.DefaultPort, "HTTP port for web dashboard (shorthand)")
	flag.BoolVar(&flagSync, "sync", false, "Execute headlessly to sync latest CISA KEV catalog and exit")
	flag.StringVar(&flagDB, "db", "", "Path to SQLite database (default: $XDG_DATA_HOME/cvegrid/cvegrid.db)")
	flag.StringVar(&flagFeed, "feed", ingestion.DefaultFeedURL, "Threat intelligence feed URL")
	flag.BoolVar(&flagVersion, "version", false, "Print version information and exit")
	flag.BoolVar(&flagVersion, "v", false, "Print version information and exit (shorthand)")
	flag.Parse()

	if flagVersion {
		fmt.Printf("cvegrid v%s (dual-engine: Terminal TUI + Web Console, zero-CGO)\n", Version)
		os.Exit(0)
	}

	// Background daemon via flags: -w -d or --daemon
	if flagDaemon {
		handleDaemonStart(flagPort, flagDB, flagFeed, msg)
		return
	}

	// Resolve database path
	dbPath := flagDB
	if dbPath == "" {
		var err error
		dbPath, err = config.GetDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving database path: %v\n", err)
			os.Exit(1)
		}
	}

	// Initialize SQLite database
	db, err := database.OpenDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	repo := database.NewRepository(db)
	client := ingestion.NewHTTPClient(ingestion.DefaultTimeout)
	syncer := ingestion.NewSynchronizer(client, repo, flagFeed)

	// Headless sync mode
	if flagSync {
		fmt.Println("⚡ Fetching and synchronizing CISA Known Exploited Vulnerabilities...")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		count, err := syncer.Run(ctx, func(processed int) {
			fmt.Printf("\rProcessed %d vulnerabilities...", processed)
		})
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Sync failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Successfully ingested %d threat records into %s\n", count, dbPath)
		os.Exit(0)
	}

	// Interactive mode selection if no flags were provided
	runWebMode := flagWeb
	if !flagWeb && !flagTUI {
		if isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd()) {
			fmt.Println("\n" + msg.InteractiveTitle)
			fmt.Println(msg.InteractivePrompt)
			fmt.Println(msg.InteractiveChoiceTUI)
			fmt.Println(msg.InteractiveChoiceWeb)
			fmt.Print(msg.InteractiveChoiceInput)

			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "2" {
				runWebMode = true
			}
		}
	}

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	if runWebMode {
		runForegroundWeb(repo, syncer, flagPort, sigChan)
		return
	}

	// Terminal TUI Mode
	app := ui.NewAppModel(repo, syncer)
	p := tea.NewProgram(app, tea.WithAltScreen())

	go func() {
		<-sigChan
		p.Quit()
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Application error: %v\n", err)
		os.Exit(1)
	}
}

func runForegroundWeb(repo *database.Repository, syncer *ingestion.Synchronizer, port int, sigChan chan os.Signal) {
	server := web.NewServer(repo, syncer, port)

	// Dynamic port hunting
	ln, boundPort, err := server.BindListener()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to bind port: %v\n", err)
		os.Exit(1)
	}

	if boundPort != port && port != web.DefaultPort {
		fmt.Printf("Port %d busy. Dynamically hunting -> bound to port %d\n", port, boundPort)
	}

	// Auto-sync in background if database has no records
	if repo.Count() == 0 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			_, _ = syncer.Run(ctx, nil)
		}()
	}

	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = web.OpenBrowser(server.Addr())
	}()

	go func() {
		<-sigChan
		fmt.Println("\nGracefully shutting down web server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("\n⚡ \033[1;36mCVEGRID Web Threat Console\033[0m running at: \033[1;32m%s\033[0m\n", server.Addr())
	fmt.Println("🌐 Browser session initiated. Press Ctrl+C to terminate.")

	if err := server.StartWithListener(ln); err != nil && err.Error() != "http: Server closed" {
		fmt.Fprintf(os.Stderr, "Web server error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func handleWebSubcommand(args []string, msg locale.Messages) {
	if len(args) == 0 {
		// Just "cvegrid web" -> foreground web
		subFlags := flag.NewFlagSet("web", flag.ExitOnError)
		port := subFlags.Int("port", web.DefaultPort, "Port")
		subFlags.IntVar(port, "p", web.DefaultPort, "Port (shorthand)")
		dbPath := subFlags.String("db", "", "Database path")
		feed := subFlags.String("feed", ingestion.DefaultFeedURL, "Feed URL")
		_ = subFlags.Parse(args)

		runWebForegroundFromSubcommand(*port, *dbPath, *feed)
		return
	}

	subcmd := args[0]
	switch subcmd {
	case "start":
		subFlags := flag.NewFlagSet("web start", flag.ExitOnError)
		port := subFlags.Int("port", web.DefaultPort, "Port")
		subFlags.IntVar(port, "p", web.DefaultPort, "Port (shorthand)")
		dbPath := subFlags.String("db", "", "Database path")
		feed := subFlags.String("feed", ingestion.DefaultFeedURL, "Feed URL")
		_ = subFlags.Parse(args[1:])

		handleDaemonStart(*port, *dbPath, *feed, msg)

	case "stop":
		state, err := daemon.Stop()
		if err != nil {
			fmt.Println(msg.DaemonNotRunning)
			os.Exit(0)
		}
		fmt.Printf(msg.DaemonStopped+"\n", state.PID)
		os.Exit(0)

	case "status":
		state, running, _ := daemon.Status()
		if !running || state == nil {
			fmt.Println(msg.DaemonStatusInactive)
			os.Exit(0)
		}
		uptime := locale.FormatDuration(time.Since(state.StartTime))
		fmt.Printf(msg.DaemonStatusActive+"\n", state.PID, state.Port, state.URL, uptime)
		os.Exit(0)

	default:
		fmt.Printf("Unknown web command: %q. Usage: cvegrid web [start|stop|status]\n", subcmd)
		os.Exit(1)
	}
}

func handleDaemonStart(port int, dbPath, feed string, msg locale.Messages) {
	state, err := daemon.Start(port, dbPath, feed)
	if err != nil {
		if strings.Contains(err.Error(), "already running") && state != nil {
			fmt.Printf(msg.DaemonAlreadyRunning+"\n", state.PID, state.Port, state.URL)
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(msg.DaemonStarted+"\n", state.PID, state.Port, state.URL)
	os.Exit(0)
}

func runWebForegroundFromSubcommand(port int, dbPath, feed string) {
	if dbPath == "" {
		dbPath, _ = config.GetDBPath()
	}
	db, err := database.OpenDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	repo := database.NewRepository(db)
	client := ingestion.NewHTTPClient(ingestion.DefaultTimeout)
	syncer := ingestion.NewSynchronizer(client, repo, feed)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	runForegroundWeb(repo, syncer, port, sigChan)
}

// runDaemonWorker is executed in the background detached process.
func runDaemonWorker() {
	workerFlags := flag.NewFlagSet("__daemon_worker", flag.ExitOnError)
	port := workerFlags.Int("port", web.DefaultPort, "HTTP Port")
	dbPath := workerFlags.String("db", "", "Database path")
	feed := workerFlags.String("feed", ingestion.DefaultFeedURL, "Feed URL")
	_ = workerFlags.Parse(os.Args[2:])

	actualDBPath := *dbPath
	if actualDBPath == "" {
		var err error
		actualDBPath, err = config.GetDBPath()
		if err != nil {
			os.Exit(1)
		}
	}

	db, err := database.OpenDB(actualDBPath)
	if err != nil {
		os.Exit(1)
	}
	defer db.Close()

	repo := database.NewRepository(db)
	client := ingestion.NewHTTPClient(ingestion.DefaultTimeout)
	syncer := ingestion.NewSynchronizer(client, repo, *feed)

	server := web.NewServer(repo, syncer, *port)
	ln, boundPort, err := server.BindListener()
	if err != nil {
		os.Exit(1)
	}

	// Persist state metadata in PID file
	state := daemon.State{
		PID:       os.Getpid(),
		Port:      boundPort,
		StartTime: time.Now().UTC(),
		URL:       server.Addr(),
	}
	_ = daemon.WritePID(state)

	// Clean up PID file on exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		_ = daemon.RemovePID()
		os.Exit(0)
	}()

	// Auto-sync if database is empty
	if repo.Count() == 0 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			_, _ = syncer.Run(ctx, nil)
		}()
	}

	if err := server.StartWithListener(ln); err != nil {
		_ = daemon.RemovePID()
		os.Exit(1)
	}
}
