package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

var errAdminSelfTestRunning = errors.New("self test already running")

type adminSelfTestState struct {
	Running    bool
	RunID      int64
	StartedAt  time.Time
	LastReport *SelfTestReport
}

type adminSelfTestSnapshot struct {
	Running    bool
	RunID      int64
	StartedAt  time.Time
	LastReport *SelfTestReport
}

func (s *Server) handleAdminSelfTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.adminSelfTestPayload(s.selfTestSnapshot()))
}

func (s *Server) handleAdminSelfTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snap, err := s.startAdminSelfTest()
	if err != nil {
		if errors.Is(err, errAdminSelfTestRunning) {
			writeJSON(w, http.StatusConflict, s.adminSelfTestPayload(snap))
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.store.LogEvent(EventAdminSelf, systemOwner, "admin-http", nil, "action", "run", "run_id", fmt.Sprintf("%d", snap.RunID))
	writeJSON(w, http.StatusAccepted, s.adminSelfTestPayload(snap))
}

func (s *Server) startAdminSelfTest() (adminSelfTestSnapshot, error) {
	s.selfTestMu.Lock()
	if s.selfTestState.Running {
		snap := s.selfTestSnapshotLocked()
		s.selfTestMu.Unlock()
		return snap, errAdminSelfTestRunning
	}

	s.selfTestState.RunID++
	s.selfTestState.Running = true
	s.selfTestState.StartedAt = time.Now().UTC()
	s.selfTestState.LastReport = nil
	runID := s.selfTestState.RunID
	snap := s.selfTestSnapshotLocked()
	s.selfTestMu.Unlock()

	go func() {
		defer recoverAndLogPanic(s.logger.With("run_id", runID), "admin self test")
		report := RunSelfTestWithReport(s, s.cfg, s.logger)
		if report.StartedAt.IsZero() {
			report.StartedAt = time.Now().UTC()
		}
		if report.FinishedAt.IsZero() {
			report.FinishedAt = time.Now().UTC()
		}
		if report.Duration <= 0 {
			report.Duration = report.FinishedAt.Sub(report.StartedAt)
			if report.Duration < 0 {
				report.Duration = 0
			}
		}

		s.selfTestMu.Lock()
		defer s.selfTestMu.Unlock()
		if s.selfTestState.RunID != runID {
			return
		}
		s.selfTestState.Running = false
		s.selfTestState.LastReport = cloneSelfTestReport(&report)
	}()

	return snap, nil
}

func (s *Server) selfTestSnapshot() adminSelfTestSnapshot {
	s.selfTestMu.Lock()
	defer s.selfTestMu.Unlock()
	return s.selfTestSnapshotLocked()
}

func (s *Server) selfTestSnapshotLocked() adminSelfTestSnapshot {
	return adminSelfTestSnapshot{
		Running:    s.selfTestState.Running,
		RunID:      s.selfTestState.RunID,
		StartedAt:  s.selfTestState.StartedAt,
		LastReport: cloneSelfTestReport(s.selfTestState.LastReport),
	}
}

func cloneSelfTestReport(in *SelfTestReport) *SelfTestReport {
	if in == nil {
		return nil
	}

	out := *in
	if len(in.Suites) == 0 {
		out.Suites = nil
		return &out
	}

	out.Suites = make([]SelfTestSuiteReport, len(in.Suites))
	for i := range in.Suites {
		out.Suites[i] = in.Suites[i]
		if len(in.Suites[i].Steps) == 0 {
			out.Suites[i].Steps = nil
		} else {
			out.Suites[i].Steps = make([]SelfTestStepReport, len(in.Suites[i].Steps))
			copy(out.Suites[i].Steps, in.Suites[i].Steps)
		}
		if len(in.Suites[i].UserActions) == 0 {
			out.Suites[i].UserActions = nil
			continue
		}

		out.Suites[i].UserActions = make([]SelfTestUserActionsReport, len(in.Suites[i].UserActions))
		for j := range in.Suites[i].UserActions {
			out.Suites[i].UserActions[j] = in.Suites[i].UserActions[j]
			if len(in.Suites[i].UserActions[j].Sessions) == 0 {
				out.Suites[i].UserActions[j].Sessions = nil
				continue
			}

			out.Suites[i].UserActions[j].Sessions = make([]SelfTestSessionActionsReport, len(in.Suites[i].UserActions[j].Sessions))
			for k := range in.Suites[i].UserActions[j].Sessions {
				out.Suites[i].UserActions[j].Sessions[k] = in.Suites[i].UserActions[j].Sessions[k]
				if len(in.Suites[i].UserActions[j].Sessions[k].Actions) == 0 {
					out.Suites[i].UserActions[j].Sessions[k].Actions = nil
					continue
				}
				out.Suites[i].UserActions[j].Sessions[k].Actions = make([]SelfTestActionEvent, len(in.Suites[i].UserActions[j].Sessions[k].Actions))
				copy(out.Suites[i].UserActions[j].Sessions[k].Actions, in.Suites[i].UserActions[j].Sessions[k].Actions)
			}
		}
	}

	return &out
}

func (s *Server) adminSelfTestPayload(snap adminSelfTestSnapshot) map[string]any {
	out := map[string]any{
		"running": snap.Running,
		"run_id":  snap.RunID,
	}

	if !snap.StartedAt.IsZero() {
		out["started_at"] = snap.StartedAt.Format(time.RFC3339)
		if snap.Running {
			out["running_for"] = time.Since(snap.StartedAt).Round(time.Millisecond).String()
		}
	}

	out["last_report"] = renderSelfTestReport(snap.LastReport)

	return out
}

func renderSelfTestReport(report *SelfTestReport) any {
	if report == nil {
		return nil
	}

	suites := make([]map[string]any, 0, len(report.Suites))
	for _, suite := range report.Suites {
		steps := make([]map[string]any, 0, len(suite.Steps))
		for _, step := range suite.Steps {
			want := "ok"
			if step.WantFail {
				want = "fail"
			}

			got := "ok"
			if step.Skipped {
				got = "skip"
			} else if step.Error != "" {
				got = "fail"
			}

			result := "PASS"
			if step.Skipped {
				result = "SKIP"
			} else if !step.Passed {
				result = "FAIL"
			}

			steps = append(steps, map[string]any{
				"name":      step.Name,
				"result":    result,
				"want":      want,
				"got":       got,
				"want_fail": step.WantFail,
				"skipped":   step.Skipped,
				"passed":    step.Passed,
				"error":     step.Error,
				"note":      step.Note,
				"duration":  step.Duration.Round(time.Millisecond).String(),
			})
		}

		users := make([]map[string]any, 0, len(suite.UserActions))
		for _, user := range suite.UserActions {
			sessions := make([]map[string]any, 0, len(user.Sessions))
			for _, session := range user.Sessions {
				actions := make([]map[string]any, 0, len(session.Actions))
				for _, action := range session.Actions {
					actions = append(actions, map[string]any{
						"id":        action.ID,
						"timestamp": action.Timestamp,
						"time":      action.Time,
						"event":     action.Event,
						"path":      action.Path,
						"meta":      action.Meta,
					})
				}
				sessions = append(sessions, map[string]any{
					"session":      session.Session,
					"ip":           session.IP,
					"started_at":   session.StartedAt,
					"ended_at":     session.EndedAt,
					"duration_sec": session.DurationSec,
					"actions":      actions,
				})
			}

			users = append(users, map[string]any{
				"user_id":    user.UserID,
				"user_label": user.UserLabel,
				"sessions":   sessions,
			})
		}

		suites = append(suites, map[string]any{
			"name":         suite.Name,
			"passed":       suite.Passed,
			"failed":       suite.Failed,
			"skipped":      suite.Skipped,
			"duration":     suite.Duration.Round(time.Millisecond).String(),
			"started_at":   suite.StartedAt.Format(time.RFC3339),
			"finished_at":  suite.FinishedAt.Format(time.RFC3339),
			"steps":        steps,
			"user_actions": users,
		})
	}

	return map[string]any{
		"started_at":  report.StartedAt.Format(time.RFC3339),
		"finished_at": report.FinishedAt.Format(time.RFC3339),
		"duration":    report.Duration.Round(time.Millisecond).String(),
		"passed":      report.Passed,
		"failed":      report.Failed,
		"skipped":     report.Skipped,
		"error":       report.Error,
		"suites":      suites,
	}
}
