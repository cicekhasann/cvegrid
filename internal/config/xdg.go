package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	AppName = "cvegrid"
	DBFile  = "cvegrid.db"
	PIDFile = "cvegrid.pid"
)

// GetDataDir resolves the base data directory following the XDG Base Directory specification.
// It checks $XDG_DATA_HOME/cvegrid, falling back to ~/.local/share/cvegrid.
func GetDataDir() (string, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not determine user home directory: %w", err)
		}
		dataHome = filepath.Join(home, ".local", "share")
	}

	appDir := filepath.Join(dataHome, AppName)
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create data directory %q: %w", appDir, err)
	}

	return appDir, nil
}

// GetDBPath returns the absolute path to the SQLite database file.
func GetDBPath() (string, error) {
	dataDir, err := GetDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, DBFile), nil
}

// GetPIDFilePath resolves the PID file path adhering to XDG runtime or data directory specs.
func GetPIDFilePath() (string, error) {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir != "" {
		return filepath.Join(runtimeDir, PIDFile), nil
	}
	dataDir, err := GetDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, PIDFile), nil
}
