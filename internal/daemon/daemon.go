package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/cicekhasann/cvegrid/internal/config"
	"github.com/cicekhasann/cvegrid/internal/web"
)

// State represents persistent runtime state of the daemon.
type State struct {
	PID       int       `json:"pid"`
	Port      int       `json:"port"`
	StartTime time.Time `json:"start_time"`
	URL       string    `json:"url"`
}

// WritePID writes daemon state to the PID file.
func WritePID(state State) error {
	path, err := config.GetPIDFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ReadPID reads daemon state from the PID file.
func ReadPID() (*State, error) {
	path, err := config.GetPIDFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// RemovePID deletes the PID file.
func RemovePID() error {
	path, err := config.GetPIDFilePath()
	if err != nil {
		return err
	}
	_ = os.Remove(path)
	return nil
}

// IsProcessAlive checks whether the given PID is actively running.
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// Start launches the daemon in background.
func Start(port int, dbPath, feedURL string) (*State, error) {
	// First check if already running
	existing, err := ReadPID()
	if err == nil && existing != nil && IsProcessAlive(existing.PID) {
		return existing, fmt.Errorf("daemon is already running with PID %d", existing.PID)
	}
	_ = RemovePID()

	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("could not determine executable path: %w", err)
	}

	args := []string{"__daemon_worker"}
	if port > 0 {
		args = append(args, "-port", fmt.Sprintf("%d", port))
	}
	if dbPath != "" {
		args = append(args, "-db", dbPath)
	}
	if feedURL != "" {
		args = append(args, "-feed", feedURL)
	}

	cmd := exec.Command(self, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Detach from parent terminal session
	}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start background daemon: %w", err)
	}

	// Poll until child writes the PID file (up to 3 seconds)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state, err := ReadPID()
		if err == nil && state != nil && IsProcessAlive(state.PID) {
			_ = web.OpenBrowser(state.URL)
			return state, nil
		}
		time.Sleep(50 * time.Millisecond)
	}

	// If failed to read PID file, check if process died
	if !IsProcessAlive(cmd.Process.Pid) {
		return nil, fmt.Errorf("daemon process terminated prematurely")
	}

	// Fallback state if PID file was slow to flush
	state := &State{
		PID:       cmd.Process.Pid,
		Port:      port,
		StartTime: time.Now().UTC(),
		URL:       fmt.Sprintf("http://127.0.0.1:%d", port),
	}
	_ = WritePID(*state)
	_ = web.OpenBrowser(state.URL)
	return state, nil
}

// Stop terminates the running daemon gracefully.
func Stop() (*State, error) {
	state, err := ReadPID()
	if err != nil || state == nil {
		return nil, fmt.Errorf("no daemon PID file found")
	}

	if !IsProcessAlive(state.PID) {
		_ = RemovePID()
		return state, fmt.Errorf("process with PID %d was not running", state.PID)
	}

	proc, err := os.FindProcess(state.PID)
	if err != nil {
		_ = RemovePID()
		return state, err
	}

	// Send SIGTERM
	_ = proc.Signal(syscall.SIGTERM)

	// Await termination up to 4 seconds
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if !IsProcessAlive(state.PID) {
			_ = RemovePID()
			return state, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill if not stopped
	_ = proc.Kill()
	_ = RemovePID()
	return state, nil
}

// Status inspects the current daemon state.
func Status() (*State, bool, error) {
	state, err := ReadPID()
	if err != nil || state == nil {
		return nil, false, nil
	}

	if !IsProcessAlive(state.PID) {
		_ = RemovePID()
		return nil, false, nil
	}

	return state, true, nil
}
