package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFullFlow(t *testing.T) {
	cfg := Config{
		BaseURL: "http://127.0.0.1:8080",
		Token:   "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJ1aWQiOjc3LCJ2IjoiMjAyMzA5MjAxMDAwIn0.Wbbi1738jgF0OH5cbzCLQJsXD6wPdK_leD3QwsSHSPU4DfcuOL5sppGSFkmk4SHq",
		UID:     77,
		RID:     3,
		TempDir: filepath.Join(os.TempDir(), "usersave-rt"),
	}

	if err := RunFullFlow(context.Background(), cfg, WithLogger(t.Logf)); err != nil {
		t.Fatal(err)
	}
}
