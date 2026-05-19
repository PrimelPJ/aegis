// Package api exposes the audit log over HTTP. Every ingested event is
// run through the detection engine; findings are written back into the
// same tamper-evident log.
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/PrimelPJ/aegis/internal/audit"
	"github.com/PrimelPJ/aegis/internal/detect"
	"github.com/PrimelPJ/aegis/internal/store"
)

// Server wires the store and detection engine to HTTP handlers.
type Server struct {
	st     *store.Store
	engine *detect.Engine
	log    *log.Logger
}

func New(st *store.Store, engine *detect.Engine, l *log.Logger) *Server {
	return &Server{st: st, engine: engine, log: l}
}

// Routes returns the configured HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /v1/events", s.handleIngest)
	mux.HandleFunc("GET /v1/events", s.handleRange)
	mux.HandleFunc("GET /v1/events/{seq}", s.handleGet)
	mux.HandleFunc("POST /v1/checkpoint", s.handleCheckpoint)
	mux.HandleFunc("GET /v1/checkpoint/latest", s.handleLatestCheckpoint)
	mux.HandleFunc("GET /v1/proof/{seq}", s.handleProof)
	mux.HandleFunc("GET /v1/verify", s.handleVerify)
	mux.HandleFunc("GET /v1/alerts", s.handleAlerts)
	return s.withLogging(mux)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Microsecond))
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"events": s.st.Len(),
	})
}

// ingestRequest is the public shape clients submit.
type ingestRequest struct {
	Actor    string            `json:"actor"`
	Action   string            `json:"action"`
	Resource string            `json:"resource"`
	Outcome  string            `json:"outcome"`
	Source   string            `json:"source"`
	Meta     map[string]string `json:"meta,omitempty"`
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var req ingestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Action == "" || req.Actor == "" {
		writeErr(w, http.StatusBadRequest, "actor and action are required")
		return
	}
	e := audit.Event{
		Actor: req.Actor, Action: req.Action, Resource: req.Resource,
		Outcome: req.Outcome, Source: req.Source, Meta: req.Meta,
	}
	sealed, err := s.st.Append(e)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Run detection. Findings are appended back into the log so the
	// detector's observations are themselves auditable and immutable.
	for _, f := range s.engine.Evaluate(&sealed) {
		if _, err := s.st.Append(f.AsEvent()); err != nil {
			s.log.Printf("warning: failed to persist finding %s: %v", f.RuleID, err)
		}
		s.log.Printf("ALERT [%s] %s subject=%s seq=%d", f.Severity, f.RuleID, f.Subject, f.TriggerSeq)
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"seq":       sealed.Seq,
		"hash":      sealed.Hash,
		"prev_hash": sealed.PrevHash,
	})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	seq, err := strconv.ParseUint(r.PathValue("seq"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "seq must be an unsigned integer")
		return
	}
	e, err := s.st.Get(seq)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handleRange(w http.ResponseWriter, r *http.Request) {
	from := parseUintDefault(r.URL.Query().Get("from"), 0)
	to := parseUintDefault(r.URL.Query().Get("to"), 0)
	events, err := s.st.Range(from, to)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(events), "events": events})
}

func (s *Server) handleCheckpoint(w http.ResponseWriter, _ *http.Request) {
	cp, err := s.st.Checkpoint()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, cp)
}

func (s *Server) handleLatestCheckpoint(w http.ResponseWriter, _ *http.Request) {
	cp, ok := s.st.LatestCheckpoint()
	if !ok {
		writeErr(w, http.StatusNotFound, "no checkpoint issued yet")
		return
	}
	writeJSON(w, http.StatusOK, cp)
}

func (s *Server) handleProof(w http.ResponseWriter, r *http.Request) {
	seq, err := strconv.ParseUint(r.PathValue("seq"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "seq must be an unsigned integer")
		return
	}
	proof, cp, err := s.st.ProveInclusion(seq)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proof": proof, "checkpoint": cp})
}

func (s *Server) handleVerify(w http.ResponseWriter, _ *http.Request) {
	res := s.st.Verify()
	code := http.StatusOK
	if !res.OK {
		code = http.StatusConflict
	}
	writeJSON(w, code, res)
}

func (s *Server) handleAlerts(w http.ResponseWriter, _ *http.Request) {
	f := s.engine.Findings()
	writeJSON(w, http.StatusOK, map[string]any{"count": len(f), "findings": f})
}

func parseUintDefault(s string, def uint64) uint64 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return def
	}
	return v
}
