package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cicekhasann/cvegrid/internal/database"
	"github.com/cicekhasann/cvegrid/internal/ingestion"
	"github.com/cicekhasann/cvegrid/internal/model"
)

//go:embed assets/*
var assetsFS embed.FS

// Server hosts the Web Threat Console and REST API.
type Server struct {
	repo       *database.Repository
	syncer     *ingestion.Synchronizer
	port       int
	syncMu     sync.Mutex
	isSyncing  bool
	syncErr    error
	httpServer *http.Server
}

const DefaultPort = 19840

// NewServer initializes the embedded Web Server.
func NewServer(repo *database.Repository, syncer *ingestion.Synchronizer, port int) *Server {
	if port <= 0 {
		port = DefaultPort
	}
	return &Server{
		repo:   repo,
		syncer: syncer,
		port:   port,
	}
}

// Handler returns the configured http.Handler with API routes and embedded assets.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// REST API Routes
	mux.HandleFunc("/api/vulnerabilities", s.handleVulnerabilities)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/sync", s.handleSync)

	// Embedded static file server
	subFS, err := fs.Sub(assetsFS, "assets")
	if err == nil {
		fileServer := http.FileServer(http.FS(subFS))
		mux.Handle("/", fileServer)
	}

	return mux
}

// BindListener performs smart port hunting starting from targeted port,
// scanning forward up to +10 ports, and falling back to :0 if all are occupied.
func (s *Server) BindListener() (net.Listener, int, error) {
	startPort := s.port
	if startPort <= 0 {
		startPort = DefaultPort
	}

	// Scan targeted port up to +10 forward ports
	const maxForwardScans = 11
	for i := 0; i < maxForwardScans; i++ {
		candidatePort := startPort + i
		addr := fmt.Sprintf("127.0.0.1:%d", candidatePort)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			s.port = candidatePort
			return ln, candidatePort, nil
		}
	}

	// Fallback to ephemeral port allocated by the OS
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to bind to any port: %w", err)
	}

	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}

	return ln, s.port, nil
}

// StartWithListener serves HTTP requests on an already bound net.Listener.
func (s *Server) StartWithListener(ln net.Listener) error {
	s.httpServer = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return s.httpServer.Serve(ln)
}

// Start hunts for an available port, binds a listener, and begins serving.
func (s *Server) Start() error {
	ln, _, err := s.BindListener()
	if err != nil {
		return err
	}
	return s.StartWithListener(ln)
}

// Port returns the currently bound TCP port.
func (s *Server) Port() int {
	return s.port
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Addr returns the listening URL with the actual bound port.
func (s *Server) Addr() string {
	return fmt.Sprintf("http://127.0.0.1:%d", s.port)
}

func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	cat := strings.TrimSpace(q.Get("category"))
	sev := strings.TrimSpace(q.Get("severity"))
	search := strings.TrimSpace(q.Get("search"))
	sort := strings.TrimSpace(q.Get("sort"))
	ransomwareOnly := q.Get("ransomware_only") == "true" || q.Get("ransomware") == "1"

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}

	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 || limit > 200 {
		limit = 50
	}

	offset := (page - 1) * limit

	filter := database.FilterOptions{
		Category:       model.Category(cat),
		Severity:       model.Severity(sev),
		RansomwareOnly: ransomwareOnly,
		SearchQuery:    search,
		SortBy:         sort,
		Limit:          limit,
		Offset:         offset,
	}

	ctx := r.Context()
	total, err := s.repo.CountFiltered(ctx, filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to count vulnerabilities: %v", err), http.StatusInternalServerError)
		return
	}

	items, err := s.repo.GetVulnerabilities(ctx, filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch vulnerabilities: %v", err), http.StatusInternalServerError)
		return
	}

	totalPages := 1
	if total > 0 {
		totalPages = (total + limit - 1) / limit
	}

	resp := map[string]any{
		"items":       items,
		"total":       total,
		"page":        page,
		"limit":       limit,
		"total_pages": totalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	stats, err := s.repo.GetStats(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch statistics: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.syncMu.Lock()
	if s.isSyncing {
		s.syncMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "already_syncing",
			"message": "A feed synchronization is currently running",
		})
		return
	}

	s.isSyncing = true
	s.syncErr = nil
	s.syncMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		_, err := s.syncer.Run(ctx, nil)

		s.syncMu.Lock()
		s.isSyncing = false
		s.syncErr = err
		s.syncMu.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "sync_started",
		"message": "Feed synchronization in progress",
	})
}

// OpenBrowser launches default browser pointing to the given URL.
func OpenBrowser(url string) error {
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
	return cmd.Start()
}
