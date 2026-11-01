package tests

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cicekhasann/cvegrid/internal/daemon"
	"github.com/cicekhasann/cvegrid/internal/locale"
	"github.com/cicekhasann/cvegrid/internal/web"
)

func TestWeb_PortHunting(t *testing.T) {
	// 1. Occupy base port 19840
	basePort := 19840
	occupiedLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", basePort))
	if err != nil {
		t.Skipf("cannot bind to base test port %d: %v", basePort, err)
	}
	defer occupiedLn.Close()

	// 2. Instantiate server targeting the busy port
	server := web.NewServer(nil, nil, basePort)
	ln, boundPort, err := server.BindListener()
	if err != nil {
		t.Fatalf("BindListener failed: %v", err)
	}
	defer ln.Close()

	// Bound port must be hunting forward (> 19840)
	if boundPort == basePort {
		t.Errorf("expected port hunting to skip occupied port %d, but got %d", basePort, boundPort)
	}
	if boundPort != basePort+1 {
		t.Logf("bound to next available port: %d", boundPort)
	}
}

func TestLocale_Detection(t *testing.T) {
	// Test Turkish detection
	t.Setenv("LANG", "tr_TR.UTF-8")
	t.Setenv("LC_ALL", "")
	if loc := locale.Detect(); loc != locale.LangTR {
		t.Errorf("expected LangTR for tr_TR.UTF-8, got %s", loc)
	}
	msgTR := locale.GetMessages(locale.LangTR)
	if !stringsContains(msgTR.InteractiveTitle, "ÇİFT MOTORLU") {
		t.Errorf("expected Turkish title, got: %s", msgTR.InteractiveTitle)
	}

	// Test English detection
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("LC_ALL", "")
	if loc := locale.Detect(); loc != locale.LangEN {
		t.Errorf("expected LangEN for en_US.UTF-8, got %s", loc)
	}
	msgEN := locale.GetMessages(locale.LangEN)
	if !stringsContains(msgEN.InteractiveTitle, "DUAL-ENGINE") {
		t.Errorf("expected English title, got: %s", msgEN.InteractiveTitle)
	}

	// Test duration formatting
	dur := 2*time.Hour + 15*time.Minute + 30*time.Second
	formatted := locale.FormatDuration(dur)
	if formatted != "2h 15m 30s" {
		t.Errorf("expected '2h 15m 30s', got %q", formatted)
	}
}

func TestDaemon_StateFile(t *testing.T) {
	// Test Process Alive
	currentPID := os.Getpid()
	if !daemon.IsProcessAlive(currentPID) {
		t.Errorf("expected current process PID %d to be alive", currentPID)
	}
	if daemon.IsProcessAlive(-9999) {
		t.Errorf("expected PID -9999 to not be alive")
	}

	// Write and read test state
	testState := daemon.State{
		PID:       currentPID,
		Port:      19840,
		StartTime: time.Now().UTC().Truncate(time.Second),
		URL:       "http://127.0.0.1:19840",
	}

	if err := daemon.WritePID(testState); err != nil {
		t.Fatalf("WritePID failed: %v", err)
	}
	defer func() { _ = daemon.RemovePID() }()

	readState, err := daemon.ReadPID()
	if err != nil {
		t.Fatalf("ReadPID failed: %v", err)
	}
	if readState.PID != testState.PID || readState.Port != testState.Port {
		t.Errorf("expected state %+v, got %+v", testState, readState)
	}

	statusState, isRunning, err := daemon.Status()
	if err != nil || !isRunning || statusState.PID != currentPID {
		t.Errorf("expected running daemon status, got isRunning=%v, err=%v", isRunning, err)
	}

	if err := daemon.RemovePID(); err != nil {
		t.Errorf("RemovePID failed: %v", err)
	}

	_, isRunningAfter, _ := daemon.Status()
	if isRunningAfter {
		t.Errorf("expected daemon to not be reported as running after PID removal")
	}
}

func stringsContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && findSubstr(s, substr)))
}

func findSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
