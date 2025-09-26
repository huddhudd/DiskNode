package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"saveserver/cmd/integration"
)

func main() {
	defaults := defaultConfig()

	baseURL := flag.String("base-url", defaults.BaseURL, "UserSave server base URL")
	token := flag.String("token", defaults.Token, "Authorization token for authenticated endpoints")
	uid := flag.Uint64("uid", uint64(defaults.UID), "User ID to operate on")
	rid := flag.Uint64("rid", uint64(defaults.RID), "Role ID to operate on")
	tempDir := flag.String("temp-dir", defaults.TempDir, "Temporary directory for task artifacts")

	flag.Parse()

	cfg := integration.Config{
		BaseURL: *baseURL,
		Token:   *token,
		UID:     uint32(*uid),
		RID:     uint32(*rid),
		TempDir: *tempDir,
	}

	if cfg.Token == "" {
		log.Fatal("token is required (set -token or USERSAVE_TOKEN)")
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := integration.RunFullFlow(context.Background(), cfg, integration.WithLogger(logger.Printf)); err != nil {
		log.Fatalf("full flow failed: %v", err)
	}

	logger.Println("all flows completed successfully")
}

type configDefaults struct {
	BaseURL string
	Token   string
	UID     uint32
	RID     uint32
	TempDir string
}

func defaultConfig() configDefaults {
	def := configDefaults{
		BaseURL: "http://127.0.0.1:8080",
		Token:   "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJ1aWQiOjc3LCJ2IjoiMjAyMzA5MjAxMDAwIn0.Wbbi1738jgF0OH5cbzCLQJsXD6wPdK_leD3QwsSHSPU4DfcuOL5sppGSFkmk4SHq",
		UID:     77,
		RID:     3,
		TempDir: filepath.Join(os.TempDir(), "usersave-rt"),
	}

	if v := os.Getenv("USERSAVE_BASE_URL"); v != "" {
		def.BaseURL = v
	}
	if v := os.Getenv("USERSAVE_TOKEN"); v != "" {
		def.Token = v
	}
	if v := os.Getenv("USERSAVE_UID"); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 32); err == nil {
			def.UID = uint32(parsed)
		}
	}
	if v := os.Getenv("USERSAVE_RID"); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 32); err == nil {
			def.RID = uint32(parsed)
		}
	}
	if v := os.Getenv("USERSAVE_TEMP_DIR"); v != "" {
		def.TempDir = v
	}

	return def
}
