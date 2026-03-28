package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.SQL == "" {
		http.Error(w, "Missing sql field", http.StatusBadRequest)
		return
	}
	if len(req.SQL) > 5000 {
		http.Error(w, "SQL too long (max 5000 chars)", http.StatusBadRequest)
		return
	}

	locale := req.Locale
	if locale == "" {
		locale = "zh"
	}

	result := checkSQL(req.SQL, locale)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("encode error: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	port := os.Getenv("SQL_ENGINE_PORT")
	if port == "" {
		port = "8081"
	}

	http.HandleFunc("/check", handleCheck)
	http.HandleFunc("/health", handleHealth)

	log.Printf("Go SQL Engine listening on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
