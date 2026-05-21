package main

import (
	"net/http"
)

func (s *Server) handleAdminLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.withLiveGeo(s.LiveAdminSnapshot()))
}

func (s *Server) withLiveGeo(snap liveAdminSnapshot) liveAdminSnapshot {
	for i := range snap.Connections {
		if loc, ok := s.geoLocation(snap.Connections[i].IP); ok {
			snap.Connections[i].Geo = loc
		}
	}
	for i := range snap.Sessions {
		if loc, ok := s.geoLocation(snap.Sessions[i].IP); ok {
			snap.Sessions[i].Geo = loc
		}
	}
	for i := range snap.Transfers {
		if loc, ok := s.geoLocation(snap.Transfers[i].IP); ok {
			snap.Transfers[i].Geo = loc
		}
	}
	return snap
}
