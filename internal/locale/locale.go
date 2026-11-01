package locale

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Language represents the active language mode.
type Language string

const (
	LangTR Language = "tr"
	LangEN Language = "en"
)

// Detect detects the system locale via LC_ALL, LANG, or LC_MESSAGES.
func Detect() Language {
	for _, env := range []string{"LC_ALL", "LANG", "LC_MESSAGES"} {
		val := strings.ToLower(os.Getenv(env))
		if strings.Contains(val, "tr") {
			return LangTR
		}
	}
	return LangEN
}

// Messages contains localized text definitions.
type Messages struct {
	InteractiveTitle       string
	InteractivePrompt      string
	InteractiveChoiceTUI   string
	InteractiveChoiceWeb   string
	InteractiveChoiceInput string

	DaemonStarted      string
	DaemonStopped      string
	DaemonNotRunning   string
	DaemonAlreadyRunning string
	DaemonStatusActive string
	DaemonStatusInactive string
	DaemonUptime       string
}

// GetMessages returns translated text structs for the current or detected language.
func GetMessages(lang ...Language) Messages {
	active := Detect()
	if len(lang) > 0 {
		active = lang[0]
	}

	if active == LangTR {
		return Messages{
			InteractiveTitle:       "⚡ \033[1;36mCVEGRID\033[0m // ÇİFT MOTORLU TEHDİT İSTİHBARATI PLATFORMU",
			InteractivePrompt:      "Başlatılacak arayüzü seçin:",
			InteractiveChoiceTUI:   "  \033[1m[1]\033[0m Terminal TUI (Siber Matris Konsolu)",
			InteractiveChoiceWeb:   "  \033[1m[2]\033[0m Web Tehdit Konsolu (Karanlık SOC Web Arayüzü)",
			InteractiveChoiceInput: "\nSeçiminiz [1-2] (varsayılan: 1): ",

			DaemonStarted:        "✓ Web servisi arka planda başlatıldı (PID: %d, Port: %d)\n🌐 URL: %s\n🚀 Tarayıcı oturumu açıldı.",
			DaemonStopped:        "✓ Arka plan servisi durduruldu (PID: %d).",
			DaemonNotRunning:     "ℹ Çalışan bir cvegrid arka plan servisi bulunamadı.",
			DaemonAlreadyRunning: "⚠ cvegrid servisi zaten çalışıyor (PID: %d, Port: %d, URL: %s).",
			DaemonStatusActive:   "● Durum: ÇALIŞIYOR (PID: %d, Port: %d)\n  URL: %s\n  Çalışma Süresi: %s",
			DaemonStatusInactive: "○ Durum: ÇALIŞMIYOR",
			DaemonUptime:         "Çalışma Süresi",
		}
	}

	return Messages{
		InteractiveTitle:       "⚡ \033[1;36mCVEGRID\033[0m // DUAL-ENGINE THREAT OPERATIONS PLATFORM",
		InteractivePrompt:      "Select runtime interface:",
		InteractiveChoiceTUI:   "  \033[1m[1]\033[0m Terminal TUI (Cyber Matrix Workstation)",
		InteractiveChoiceWeb:   "  \033[1m[2]\033[0m Web Threat Console (Dark SOC Web Interface)",
		InteractiveChoiceInput: "\nChoice [1-2] (default: 1): ",

		DaemonStarted:        "✓ Web service started in background (PID: %d, Port: %d)\n🌐 URL: %s\n🚀 Browser session launched.",
		DaemonStopped:        "✓ Background service stopped (PID: %d).",
		DaemonNotRunning:     "ℹ No active cvegrid background service found.",
		DaemonAlreadyRunning: "⚠ cvegrid service is already running (PID: %d, Port: %d, URL: %s).",
		DaemonStatusActive:   "● Status: RUNNING (PID: %d, Port: %d)\n  URL: %s\n  Uptime: %s",
		DaemonStatusInactive: "○ Status: STOPPED",
		DaemonUptime:         "Uptime",
	}
}

// FormatDuration formats an elapsed time duration human-readably.
func FormatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
