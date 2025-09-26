package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"saveserver/nvfiles"
	"saveserver/nvservice/config"
	"saveserver/nvservice/server"
	"saveserver/nvservice/storage"
)

func main() {
	baseDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("get working dir: %v", err)
	}

	iniPath := filepath.Join(baseDir, "CloudStart.ini")
	cacheDirs, err := config.ParseUserCachePaths(iniPath)
	if err != nil {
		log.Fatalf("parse CloudStart.ini: %v", err)
	}

	dataFactory, err := storage.NewDataFactory(cacheDirs)
	if err != nil {
		log.Fatalf("init data factory: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbPath := filepath.Join(baseDir, "Data", "NvFiles.db")
	store, err := nvfiles.Open(ctx, dbPath)
	if err != nil {
		log.Fatalf("open NvFiles db: %v", err)
	}
	defer store.Close()

	srv, err := server.New(baseDir, store, dataFactory)
	if err != nil {
		log.Fatalf("init server: %v", err)
	}

	mux := http.NewServeMux()
	srv.Register(mux)

	httpServer := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		log.Printf("NvCache service listening on %s", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}
