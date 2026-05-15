package main

import (
	"net/http"
)

func (s *Server) handleAdminLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.LiveAdminSnapshot())
}
