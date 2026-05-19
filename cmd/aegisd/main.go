// Command aegisd runs the tamper-evident audit log server.
//
//	aegisd -addr :8080 -data ./data -rules configs/rules.json
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/PrimelPJ/aegis/internal/api"
	"github.com/PrimelPJ/aegis/internal/detect"
	"github.com/PrimelPJ/aegis/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dataDir := flag.String("data", "./data", "data directory")
	rulesPath := flag.String("rules", "", "detection rules JSON (built-in defaults if empty)")
	segSize := flag.Int64("segment-size", store.DefaultMaxSegmentSize, "max segment size in bytes")
	flag.Parse()

	logger := log.New(os.Stdout, "aegis ", log.LstdFlags|log.Lmsgprefix)

	st, err := store.Open(*dataDir, *segSize)
	if err != nil {
		logger.Fatalf("open store: %v", err)
	}
	defer st.Close()

	rules, err := detect.LoadRules(*rulesPath)
	if err != nil {
		logger.Fatalf("load rules: %v", err)
	}
	logger.Printf("loaded %d detection rules; %d events recovered", len(rules), st.Len())

	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.New(st, detect.NewEngine(rules), logger).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Printf("listening on %s (data=%s)", *addr, *dataDir)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Println("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Printf("shutdown error: %v", err)
	}
}
