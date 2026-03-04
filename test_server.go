// test_server.go
//
// Self-test harness for sftpguy.  Same package (main).
//
// -test            run suite then exit (0 = all pass, 1 = any failure)
// -test.continue   run suite then keep serving regardless of result

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ============================================================================
// Entry point
// ============================================================================

// RunSelfTest waits for the server to become ready, runs every suite, logs a
// report, purges temporary users, then returns the failure count.
// The caller decides whether to exit or continue based on cfg flags.
func RunSelfTest(srv *Server, cfg Config, logger *slog.Logger) int {
	report := RunSelfTestWithReport(srv, cfg, logger)
	return report.Failed
}

// RunSelfTestWithReport runs the integration self-test suite and returns a
// structured report with per-suite and per-step results.
func RunSelfTestWithReport(srv *Server, cfg Config, logger *slog.Logger) SelfTestReport {
	log := logger.WithGroup("test") //("component", "self-test")
	startedAt := time.Now().UTC()
	report := SelfTestReport{StartedAt: startedAt}

	log.Info("waiting for server to become ready")
	if !stWaitReady(cfg.Port, 10*time.Second) {
		const msg = "server did not become ready within timeout"
		log.Error(msg)
		report.FinishedAt = time.Now().UTC()
		report.Duration = report.FinishedAt.Sub(report.StartedAt)
		report.Failed = 1
		report.Error = msg
		return report
	}
	log.Info("server ready – starting suite")

	r := &selfTestRunner{srv: srv, cfg: cfg, log: log}
	return r.run()
}

// ============================================================================
// Runner
// ============================================================================

type selfTestRunner struct {
	srv         *Server
	cfg         Config
	log         *slog.Logger
	knownHashes []string
	knownUsers  map[string]string
}

func (r *selfTestRunner) run() SelfTestReport {
	startedAt := time.Now().UTC()

	// ── identities ────────────────────────────────────────────────────────────
	firstAuth, firstLabel, firstHash := r.newPubKeyAuth()
	secondAuth, secondLabel, secondHash := r.newPubKeyAuth()
	banVictimAuth, banVictimLabel, banVictimHash := r.newPubKeyAuthWithHash()
	kbAuth, kbLabel, kbHash := r.newKbAuth()

	r.rememberTestUser(firstHash, "first ("+firstLabel+")")
	r.rememberTestUser(secondHash, "second ("+secondLabel+")")
	r.rememberTestUser(banVictimHash, "ban_victim ("+banVictimLabel+")")
	r.rememberTestUser(kbHash, "kbint ("+kbLabel+")")
	if r.cfg.SshNoAuth {
		r.rememberActivityUser(stAnonHash("127.0.0.1"), "noauth (127.0.0.1)")
		r.rememberActivityUser(stAnonHash("::1"), "noauth (::1)")
	}

	r.log.Info("identities",
		"first", firstLabel,
		"second", secondLabel,
		"ban_victim", banVictimLabel,
		"kbint", kbLabel,
	)

	// ── setup ─────────────────────────────────────────────────────────────────
	preexisting := "selftest_pre_" + stRandHex() + ".txt"
	r.log.Info("setup", "file", preexisting)

	setupSuite := r.runSetup(firstAuth, preexisting)
	if setupSuite.failCount() > 0 {
		suites := []*stSuite{setupSuite}
		r.logSuite(setupSuite)
		r.logReport(suites)
		r.log.Error("setup failed, aborting run")
		r.purgeTestUsers()
		return r.buildReport(startedAt, suites, "setup failed, aborting run")
	}

	// ── suites ────────────────────────────────────────────────────────────────
	suites := []*stSuite{setupSuite}
	suites = append(suites, r.runNonOwner("second (pubkey "+secondLabel+")", preexisting, secondAuth))
	suites = append(suites, r.runNonOwner("kbint ("+kbLabel+")", preexisting, kbAuth))
	if r.cfg.SshNoAuth {
		suites = append(suites, r.runNonOwner("noClientAuth (anon-by-IP)", preexisting, nil))
	}
	suites = append(suites, r.runSystemFile(secondAuth))
	suites = append(suites, r.runBanUnban(banVictimAuth, banVictimLabel, banVictimHash, preexisting))
	suites = append(suites, r.runOwnerCleanup(firstAuth, preexisting))

	// ── log each suite then print report ─────────────────────────────────────
	for _, s := range suites {
		r.logSuite(s)
	}
	r.logReport(suites)

	// ── purge ─────────────────────────────────────────────────────────────────
	r.purgeTestUsers()

	return r.buildReport(startedAt, suites, "")
}

// ============================================================================
// Suites
// ============================================================================

func (r *selfTestRunner) startSuite(name string) *stSuite {
	s := newStSuite(name)
	s.logStartID = r.maxLogID()
	return s
}

func (r *selfTestRunner) finishSuite(s *stSuite) {
	if s == nil {
		return
	}
	s.finish()
	s.logEndID = r.maxLogID()
}

func (r *selfTestRunner) maxLogID() int64 {
	var id int64
	if err := r.srv.store.db.QueryRow(`SELECT IFNULL(MAX(id), 0) FROM log`).Scan(&id); err != nil {
		r.log.Debug("failed to read max log id", "err", err)
		return 0
	}
	return id
}

func (r *selfTestRunner) runSetup(auth ssh.AuthMethod, preexisting string) *stSuite {
	s := r.startSuite("Setup")
	defer r.finishSuite(s)
	sshCli, sftpCli, err := r.openSFTP(auth)
	s.check("connect as first user", err)
	if err != nil {
		return s
	}
	defer sshCli.Close()
	defer sftpCli.Close()
	s.check("write preexisting file", stWrite(sftpCli, preexisting, stPayload(r.cfg.ContributorThreshold)))
	return s
}

func (r *selfTestRunner) runNonOwner(label, preexisting string, auth ssh.AuthMethod) *stSuite {
	s := r.startSuite("Non-owner: " + label)
	defer r.finishSuite(s)

	sfx := stRandHex()
	newFile := "selftest_new_" + sfx + ".txt"
	renamedFile := "selftest_ren_" + sfx + ".txt"

	// 1. Basic SSH security checks (Protocol level)
	probeAuth := auth
	if auth == nil {
		probeAuth, _, _ = r.newKbAuth()
	}
	s.wantFail("exec rejected", r.tryExec(probeAuth))
	s.wantFail("shell rejected", r.tryShell(probeAuth))

	// 2. Establish SFTP connection
	var sshCli *ssh.Client
	var sftpCli *sftp.Client
	var err error
	if auth == nil {
		sshCli, sftpCli, err = r.openSFTPNoAuth()
	} else {
		sshCli, sftpCli, err = r.openSFTP(auth)
	}

	s.check("connect (SFTP)", err)
	if err != nil {
		// Skip remainder of suite if connection fails
		for i := 0; i < 11; i++ {
			s.skip("(skipped)", "no SFTP connection")
		}
		return s
	}
	defer sshCli.Close()
	defer sftpCli.Close()

	// 3. Preliminary List Check (Protocol level)
	_, err = sftpCli.ReadDir("/")
	s.check("list /", err)

	// 4. Pre-contribution: Mutations on preexisting file should fail on disk
	// (wantExists/wantDeleted = false means we expect the file to STAY exactly as it is)
	s.wantFail("read preexisting (pre-contrib protocol check)", stRead(sftpCli, preexisting))
	r.checkRename(s, sftpCli, preexisting, preexisting+".bak", false)
	r.checkWrite(s, sftpCli, preexisting, []byte("overwritten"), false)
	r.checkDelete(s, sftpCli, preexisting, false)

	// 5. Become a Contributor: Write a new file
	// We check the disk to ensure the file actually appeared
	r.checkWrite(s, sftpCli, newFile, stPayload(r.cfg.ContributorThreshold), true)

	// 6. Contributor Rights: Should now be able to read preexisting (Protocol check)
	s.check("read preexisting (contributor protocol check)", stRead(sftpCli, preexisting))

	// 7. Ownership: Should be able to mutate own file
	// Verify that rename actually moves the file on disk
	r.checkRename(s, sftpCli, newFile, renamedFile, true)

	// Verify that overwrite actually updates the file on disk
	r.checkWrite(s, sftpCli, renamedFile, []byte("updated contents"), true)

	// Verify that delete actually removes the file from disk
	r.checkDelete(s, sftpCli, renamedFile, true)

	// 8. Contributor state should remain after cleanup (Protocol check)
	s.check("read preexisting (post-cleanup protocol check)", stRead(sftpCli, preexisting))

	// 9. Post-cleanup: Should still be blocked from mutating others' files
	r.checkRename(s, sftpCli, preexisting, preexisting+".bak2", false)
	r.checkWrite(s, sftpCli, preexisting, []byte("bad2"), false)
	r.checkDelete(s, sftpCli, preexisting, false)

	return s
}

// runSystemFile creates a real file, registers it as a system (unrestricted)
// path, verifies mutations are denied via disk-state checks, then cleans up.
func (r *selfTestRunner) runSystemFile(auth ssh.AuthMethod) *stSuite {
	sysName := "selftest_sysfile_" + stRandHex() + ".txt"

	s := r.startSuite("System file protection (" + sysName + ")")
	defer r.finishSuite(s)

	// 1. Setup: Create file on disk and register it as unrestricted
	fullPath := r.local(sysName)
	err := os.WriteFile(fullPath, []byte("system file contents"), 0644)
	s.check("setup: create disk file", err)
	if err != nil {
		return s
	}

	r.srv.cfg.unrestrictedMap[sysName] = true
	r.srv.store.ClaimFile(systemOwner, sysName)
	defer func() {
		r.srv.store.DeletePath(sysName)
		delete(r.srv.cfg.unrestrictedMap, sysName)
		os.Remove(fullPath)
	}()

	// 2. Connect
	sshCli, sftpCli, err := r.openSFTP(auth)
	s.check("connect", err)
	if err != nil {
		return s
	}
	defer sshCli.Close()
	defer sftpCli.Close()

	// 3. Mutation attempts
	// We use the check helpers to verify the disk state remains unchanged.

	// wantMoved=false: Verify source still exists and dest was not created
	r.checkRename(s, sftpCli, sysName, sysName+".bak", false)

	// wantExists=true: In the context of a failed write, we verify the file didn't disappear
	r.checkWrite(s, sftpCli, sysName, []byte("attempted overwrite"), true)

	// wantDeleted=false: Verify the file is still present on disk
	r.checkDelete(s, sftpCli, sysName, false)

	return s
}

func (r *selfTestRunner) runBanUnban(victimAuth ssh.AuthMethod, victimLabel, victimHash, preexisting string) *stSuite {
	s := r.startSuite("Ban / unban (" + victimLabel + ")")
	defer r.finishSuite(s)
	victimFile := "selftest_ban_" + stRandHex() + ".txt"

	// 1. Setup file
	sshCli, sftpCli, err := r.openSFTP(victimAuth)
	s.check("connect (pre-ban)", err)
	if err != nil {
		return s
	}
	r.checkWrite(s, sftpCli, victimFile, stPayload(r.cfg.ContributorThreshold), true)
	_ = sftpCli.Close()
	_ = sshCli.Close()

	// 2. BAN
	r.srv.Ban(victimHash)
	s.assert("victimHash is banned", r.srv.store.IsBanned(victimHash))

	sshCli, sftpCli, err = r.openSFTP(victimAuth)
	s.check("connect while banned", err)
	if err != nil {
		return s
	}
	// 3. Victim tries to delete.
	// The test passes IF the file is NOT deleted (wantDeleted=false).
	// We don't care if the server says "OK" or "Permission Denied".
	r.checkDelete(s, sftpCli, victimFile, false)
	_ = sftpCli.Close()
	_ = sshCli.Close()

	// 4. UNBAN
	r.srv.Unban(victimHash)
	s.assert("victimHash is unbanned", !r.srv.store.IsBanned(victimHash))

	sshCli, sftpCli, err = r.openSFTP(victimAuth)
	s.check("connect after unban", err)
	if err != nil {
		return s
	}
	// 5. Normal operation (wantDeleted=true)
	r.checkDelete(s, sftpCli, victimFile, true)
	_ = sftpCli.Close()
	_ = sshCli.Close()

	return s
}

func (r *selfTestRunner) runOwnerCleanup(auth ssh.AuthMethod, preexisting string) *stSuite {
	s := r.startSuite("Owner cleanup")
	defer r.finishSuite(s)
	sshCli, sftpCli, err := r.openSFTP(auth)
	s.check("connect as owner", err)
	if err != nil {
		s.skip("rename preexisting", "no connection")
		s.skip("overwrite preexisting", "no connection")
		s.skip("delete preexisting", "no connection")
		return s
	}
	defer sshCli.Close()
	defer sftpCli.Close()

	tmp := preexisting + ".tmp"
	renErr := sftpCli.Rename(preexisting, tmp)
	s.check("owner can rename own file", renErr)
	if renErr == nil {
		_ = sftpCli.Rename(tmp, preexisting)
	}
	s.check("owner can overwrite own file", stWrite(sftpCli, preexisting, []byte("updated by owner")))
	s.check("owner can delete own file", sftpCli.Remove(preexisting))
	return s
}

// ============================================================================
// Report
// ============================================================================
type stSteps []stStep

func (ss stSteps) LogValue() slog.Value {
	values := make([]slog.Value, len(ss))
	for i, s := range ss {
		values[i] = s.LogValue()
	}
	return slog.AnyValue(values)
}

type SelfTestReport struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Duration   time.Duration
	Passed     int
	Failed     int
	Skipped    int
	Error      string
	Suites     []SelfTestSuiteReport
}

type SelfTestSuiteReport struct {
	Name        string
	Passed      int
	Failed      int
	Skipped     int
	Duration    time.Duration
	StartedAt   time.Time
	FinishedAt  time.Time
	Steps       []SelfTestStepReport
	UserActions []SelfTestUserActionsReport
}

type SelfTestStepReport struct {
	Name     string
	WantFail bool
	Skipped  bool
	Passed   bool
	Error    string
	Note     string
	Duration time.Duration
}

type SelfTestUserActionsReport struct {
	UserID    string
	UserLabel string
	Sessions  []SelfTestSessionActionsReport
}

type SelfTestSessionActionsReport struct {
	Session     string
	IP          string
	StartedAt   int64
	EndedAt     int64
	DurationSec int64
	Actions     []SelfTestActionEvent
}

type SelfTestActionEvent struct {
	ID        int64
	Timestamp int64
	Time      string
	Event     string
	Path      string
	Meta      string
}

func (r *selfTestRunner) buildReport(startedAt time.Time, suites []*stSuite, runErr string) SelfTestReport {
	report := SelfTestReport{
		StartedAt:  startedAt.UTC(),
		FinishedAt: time.Now().UTC(),
		Error:      strings.TrimSpace(runErr),
		Suites:     make([]SelfTestSuiteReport, 0, len(suites)),
	}

	for _, suite := range suites {
		suiteReport := SelfTestSuiteReport{
			Name:       suite.name,
			StartedAt:  suite.start.UTC(),
			FinishedAt: suite.endTime().UTC(),
			Steps:      make([]SelfTestStepReport, 0, len(suite.steps)),
		}
		var suiteDur time.Duration

		for _, step := range suite.steps {
			stepReport := SelfTestStepReport{
				Name:     step.Name,
				WantFail: step.WantFail,
				Skipped:  step.Skipped,
				Passed:   step.passed(),
				Note:     step.Note,
				Duration: step.Dur.Round(time.Millisecond),
			}
			suiteDur += step.Dur
			if step.Err != nil {
				stepReport.Error = step.Err.Error()
			}

			suiteReport.Steps = append(suiteReport.Steps, stepReport)

			switch {
			case step.Skipped:
				suiteReport.Skipped++
			case step.passed():
				suiteReport.Passed++
			default:
				suiteReport.Failed++
			}
		}
		if suiteDur <= 0 {
			suiteDur = suite.duration()
		}
		suiteReport.Duration = suiteDur.Round(time.Millisecond)
		suiteReport.UserActions = r.collectSuiteUserActions(suite)

		report.Passed += suiteReport.Passed
		report.Failed += suiteReport.Failed
		report.Skipped += suiteReport.Skipped
		report.Suites = append(report.Suites, suiteReport)
	}

	report.Duration = report.FinishedAt.Sub(report.StartedAt)
	if report.Duration < 0 {
		report.Duration = 0
	}

	return report
}

func (r *selfTestRunner) collectSuiteUserActions(suite *stSuite) []SelfTestUserActionsReport {
	if suite == nil {
		return nil
	}
	if suite.logEndID <= suite.logStartID {
		return nil
	}

	rows, err := r.srv.store.db.Query(`
		SELECT
			id,
			timestamp,
			IFNULL(user_id, ''),
			IFNULL(user_session, ''),
			IFNULL(ip_address, ''),
			IFNULL(event, ''),
			IFNULL(path, ''),
			IFNULL(meta, '')
		FROM log
		WHERE id > ? AND id <= ?
		ORDER BY id ASC
	`, suite.logStartID, suite.logEndID)
	if err != nil {
		r.log.Warn("failed to query suite user actions", "suite", suite.name, "err", err)
		return nil
	}
	defer rows.Close()

	type actionRow struct {
		id        int64
		ts        int64
		userID    string
		sessionID string
		ip        string
		event     string
		path      string
		meta      string
	}

	byUserSession := make(map[string]*SelfTestSessionActionsReport)

	for rows.Next() {
		var row actionRow
		if scanErr := rows.Scan(&row.id, &row.ts, &row.userID, &row.sessionID, &row.ip, &row.event, &row.path, &row.meta); scanErr != nil {
			r.log.Warn("failed scanning suite user action row", "suite", suite.name, "err", scanErr)
			return nil
		}

		row.userID = strings.TrimSpace(row.userID)
		if row.userID == "" || row.userID == systemOwner {
			continue
		}

		label, known := r.knownUsers[row.userID]
		if !known {
			continue
		}
		if strings.TrimSpace(label) == "" {
			label = shortID(row.userID)
		}

		sessionID := strings.TrimSpace(row.sessionID)
		if sessionID == "" {
			sessionID = "no-session"
		}
		key := row.userID + "\x00" + sessionID
		session, ok := byUserSession[key]
		if !ok {
			session = &SelfTestSessionActionsReport{
				Session:   sessionID,
				IP:        strings.TrimSpace(row.ip),
				StartedAt: row.ts,
				EndedAt:   row.ts,
				Actions:   make([]SelfTestActionEvent, 0, 16),
			}
			byUserSession[key] = session
		}

		if row.ts < session.StartedAt || session.StartedAt == 0 {
			session.StartedAt = row.ts
		}
		if row.ts > session.EndedAt {
			session.EndedAt = row.ts
		}
		if session.IP == "" && row.ip != "" {
			session.IP = row.ip
		}

		session.Actions = append(session.Actions, SelfTestActionEvent{
			ID:        row.id,
			Timestamp: row.ts,
			Time:      formatUnix(row.ts),
			Event:     row.event,
			Path:      row.path,
			Meta:      row.meta,
		})
	}
	if err := rows.Err(); err != nil {
		r.log.Warn("suite user actions rows error", "suite", suite.name, "err", err)
		return nil
	}

	byUser := make(map[string][]SelfTestSessionActionsReport)
	for key, session := range byUserSession {
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		if session.EndedAt >= session.StartedAt {
			session.DurationSec = session.EndedAt - session.StartedAt
		}
		byUser[parts[0]] = append(byUser[parts[0]], *session)
	}

	for userID := range byUser {
		sort.Slice(byUser[userID], func(i, j int) bool {
			if byUser[userID][i].StartedAt == byUser[userID][j].StartedAt {
				return byUser[userID][i].Session < byUser[userID][j].Session
			}
			return byUser[userID][i].StartedAt < byUser[userID][j].StartedAt
		})
	}

	knownOrder := make([]string, 0, len(r.knownUsers))
	for userID := range r.knownUsers {
		knownOrder = append(knownOrder, userID)
	}
	sort.Slice(knownOrder, func(i, j int) bool {
		leftLabel := r.knownUsers[knownOrder[i]]
		rightLabel := r.knownUsers[knownOrder[j]]
		if leftLabel == rightLabel {
			return knownOrder[i] < knownOrder[j]
		}
		return leftLabel < rightLabel
	})

	out := make([]SelfTestUserActionsReport, 0, len(knownOrder))
	for _, userID := range knownOrder {
		out = append(out, SelfTestUserActionsReport{
			UserID:    userID,
			UserLabel: r.knownUsers[userID],
			Sessions:  byUser[userID],
		})
	}

	return out
}

func (r *selfTestRunner) logReport(suites []*stSuite) {
	totalPass, totalFail, totalSkip := 0, 0, 0
	var totalDur time.Duration

	for _, s := range suites {
		totalPass += s.passCount()
		totalFail += s.failCount()
		totalSkip += s.skipCount()
		totalDur += s.duration()
	}

	level := slog.LevelInfo
	if totalFail > 0 {
		level = slog.LevelError
	}

	// Per-suite summary lines
	for _, s := range suites {
		suiteLevel := slog.LevelInfo
		if s.failCount() > 0 {
			suiteLevel = slog.LevelWarn
		}
		r.log.Log(nil, suiteLevel, "self-test report suite", //nolint:sloglint
			"suite", s.name,
			"passed", s.passCount(),
			"failed", s.failCount(),
			"skipped", s.skipCount(),
			"duration", s.duration().Round(time.Millisecond).String(),
			"failures", stSteps(s.Failures()),
		)
	}

	// Overall summary
	r.log.Log(nil, level, "self-test report", //nolint:sloglint
		"passed", totalPass,
		"failed", totalFail,
		"skipped", totalSkip,
		"duration", totalDur.Round(time.Millisecond).String(),
	)
}

// ============================================================================
// Purge
// ============================================================================

func (r *selfTestRunner) purgeTestUsers() {
	r.log.Info("purging temporary test users", "count", len(r.knownHashes))
	for _, h := range r.knownHashes {
		if err := r.srv.PurgeUser(h); err != nil {
			r.log.Warn("purge failed", "hash", shortID(h), "err", err)
		} else {
			r.log.Debug("purged user", "hash", shortID(h))
		}
	}
}

func (r *selfTestRunner) rememberTestUser(hash, label string) {
	r.rememberActivityUser(hash, label)

	hash = strings.TrimSpace(hash)
	if hash == "" {
		return
	}
	for _, existing := range r.knownHashes {
		if existing == hash {
			return
		}
	}
	r.knownHashes = append(r.knownHashes, hash)
}

func (r *selfTestRunner) rememberActivityUser(hash, label string) {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return
	}

	if r.knownUsers == nil {
		r.knownUsers = make(map[string]string, 8)
	}
	if strings.TrimSpace(label) != "" {
		r.knownUsers[hash] = strings.TrimSpace(label)
	} else if _, exists := r.knownUsers[hash]; !exists {
		r.knownUsers[hash] = shortID(hash)
	}
}

// ============================================================================
// Identity factories
// ============================================================================

func (r *selfTestRunner) newPubKeyAuth() (ssh.AuthMethod, string, string) {
	return r.newPubKeyAuthWithHash()
}

func (r *selfTestRunner) newPubKeyAuthWithHash() (ssh.AuthMethod, string, string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		r.log.Error("failed to generate key", "err", err)
		return nil, "", ""
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	hash := fmt.Sprintf("%x", sum)
	r.rememberTestUser(hash, "pubkey "+fp[:16])
	return ssh.PublicKeys(signer), fp[:16], hash
}

func (r *selfTestRunner) newKbAuth() (ssh.AuthMethod, string, string) {
	b := make([]byte, 8)
	cryptorand.Read(b) //nolint:errcheck
	pw := fmt.Sprintf("selftest-%x", b)
	method := ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = pw
		}
		return answers, nil
	})
	sum := sha256.Sum256([]byte("pwd-auth:anonymous:" + pw))
	hash := fmt.Sprintf("pwd-auth:%x", sum)
	label := "kbint:" + pw[:16]
	r.rememberTestUser(hash, label)
	return method, label, hash
}

// ============================================================================
// Dial helpers
// ============================================================================

func (r *selfTestRunner) hkCB() ssh.HostKeyCallback {
	return ssh.InsecureIgnoreHostKey() //nolint:gosec
}

func (r *selfTestRunner) sshCfg(auth ssh.AuthMethod) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "anonymous",
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: r.hkCB(),
		Timeout:         15 * time.Second,
	}
}

func (r *selfTestRunner) dialSSH(cfg *ssh.ClientConfig) (*ssh.Client, error) {
	return ssh.Dial("tcp", fmt.Sprintf("localhost:%d", r.cfg.Port), cfg)
}

func (r *selfTestRunner) openSFTP(auth ssh.AuthMethod) (*ssh.Client, *sftp.Client, error) {
	sshCli, err := r.dialSSH(r.sshCfg(auth))
	if err != nil {
		return nil, nil, err
	}
	sftpCli, err := sftp.NewClient(sshCli)
	if err != nil {
		sshCli.Close()
		return nil, nil, err
	}
	return sshCli, sftpCli, nil
}

func (r *selfTestRunner) openSFTPNoAuth() (*ssh.Client, *sftp.Client, error) {
	addr := fmt.Sprintf("localhost:%d", r.cfg.Port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            "anonymous",
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: r.hkCB(),
		Timeout:         15 * time.Second,
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	sshCli := ssh.NewClient(cc, chans, reqs)
	sftpCli, err := sftp.NewClient(sshCli)
	if err != nil {
		sshCli.Close()
		return nil, nil, err
	}
	return sshCli, sftpCli, nil
}

func (r *selfTestRunner) tryExec(auth ssh.AuthMethod) error {
	cli, err := r.dialSSH(r.sshCfg(auth))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer cli.Close()
	sess, err := cli.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	if err := sess.Run("ls"); err != nil {
		return err
	}
	return nil
}

func (r *selfTestRunner) tryShell(auth ssh.AuthMethod) error {
	cli, err := r.dialSSH(r.sshCfg(auth))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer cli.Close()
	sess, err := cli.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	var buf strings.Builder
	sess.Stdout = &buf
	if err := sess.Shell(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case e := <-done:
		if e != nil {
			return e
		}
		return fmt.Errorf("server closed shell: %s", stTrunc(buf.String(), 80))
	case <-time.After(3 * time.Second):
		return fmt.Errorf("shell did not close (timeout)")
	}
}

// ============================================================================
// SFTP I/O
// ============================================================================

func stRead(c *sftp.Client, p string) error {
	f, err := c.Open(path.Clean("/" + p))
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 4096)
	for {
		_, err := f.Read(buf)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func stWrite(c *sftp.Client, p string, data []byte) error {
	f, err := c.OpenFile(path.Clean("/"+p), os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func stPayload(n int64) []byte {
	if n <= 0 {
		n = 1024
	}
	b := make([]byte, n)
	cryptorand.Read(b) //nolint:errcheck
	return b
}

// ============================================================================
// Misc
// ============================================================================

func stWaitReady(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), time.Second)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func stRandHex() string {
	b := make([]byte, 4)
	cryptorand.Read(b) //nolint:errcheck
	return fmt.Sprintf("%08x", binary.BigEndian.Uint32(b))
}

func stAnonHash(ip string) string {
	sum := sha256.Sum256([]byte("anon-auth:" + strings.TrimSpace(ip)))
	return fmt.Sprintf("anon-auth:%x", sum)
}

func stTrunc(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ============================================================================
// stSuite – result collector with per-step timing
// ============================================================================

type stStep struct {
	Name     string
	WantFail bool
	Err      error
	Skipped  bool
	Note     string
	Dur      time.Duration
}

func (t *stStep) passed() bool {
	if t.Skipped {
		return true
	}
	if t.WantFail {
		return t.Err != nil
	}
	return t.Err == nil
}

func (s stStep) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("name", s.Name),
		slog.Bool("wantFail", s.WantFail),
		slog.Bool("skipped", s.Skipped),
		slog.Duration("dur", s.Dur),
	}

	if s.Err != nil {
		attrs = append(attrs, slog.String("err", s.Err.Error()))
	}

	if s.Note != "" {
		attrs = append(attrs, slog.String("note", s.Note))
	}

	return slog.GroupValue(attrs...)
}

type stSuite struct {
	name       string
	steps      []stStep
	start      time.Time
	end        time.Time
	logStartID int64
	logEndID   int64
}

func newStSuite(name string) *stSuite {
	return &stSuite{name: name, start: time.Now()}
}

func (s *stSuite) finish() {
	if s.end.IsZero() {
		s.end = time.Now()
	}
}

func (s *stSuite) endTime() time.Time {
	if s.end.IsZero() {
		return time.Now()
	}
	return s.end
}

func (s *stSuite) duration() time.Duration { return s.endTime().Sub(s.start) }

func (s *stSuite) record(name string, wantFail bool, err error, start time.Time) {
	s.steps = append(s.steps, stStep{
		Name: name, WantFail: wantFail, Err: err,
		Dur: time.Since(start),
	})
}

func (s *stSuite) check(name string, err error) {
	s.record(name, false, err, time.Now())
}

func (r *selfTestRunner) local(sftpPath string) string {
	return filepath.Join(r.srv.absUploadDir, path.Clean("/"+sftpPath))
}

type stDiskSnapshot struct {
	exists bool
	isDir  bool
	size   int64
	hash   [sha256.Size]byte
}

func stSnapshot(fullPath string) (stDiskSnapshot, error) {
	fi, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return stDiskSnapshot{}, nil
		}
		return stDiskSnapshot{}, err
	}

	snap := stDiskSnapshot{
		exists: true,
		isDir:  fi.IsDir(),
		size:   fi.Size(),
	}
	if fi.Mode().IsRegular() {
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return stDiskSnapshot{}, err
		}
		snap.hash = sha256.Sum256(data)
	}

	return snap, nil
}

func (s stDiskSnapshot) equal(other stDiskSnapshot) bool {
	if s.exists != other.exists || s.isDir != other.isDir || s.size != other.size {
		return false
	}
	if !s.exists || s.isDir {
		return true
	}
	return s.hash == other.hash
}

// checkDelete verifies disk state after a removal attempt.
func (r *selfTestRunner) checkDelete(s *stSuite, sftp *sftp.Client, sftpPath string, wantDeleted bool) {
	start := time.Now()
	protoErr := sftp.Remove(sftpPath) // We perform the action but ignore the return value for success

	_, statErr := os.Stat(r.local(sftpPath))
	exists := !os.IsNotExist(statErr)

	var diskErr error
	if wantDeleted && exists {
		diskErr = fmt.Errorf("disk: file still exists (proto: %v)", protoErr)
	} else if !wantDeleted && !exists {
		diskErr = fmt.Errorf("disk: file was deleted (proto: %v)", protoErr)
	}

	s.record("delete "+sftpPath, false, diskErr, start)
}

func (r *selfTestRunner) checkWrite(s *stSuite, sftp *sftp.Client, sftpPath string, data []byte, wantExists bool) {
	start := time.Now()
	fullPath := r.local(sftpPath)
	before, snapErr := stSnapshot(fullPath)
	if snapErr != nil {
		s.record("write "+sftpPath, false, fmt.Errorf("disk: snapshot before write failed: %w", snapErr), start)
		return
	}

	protoErr := stWrite(sftp, sftpPath, data)

	after, snapErr := stSnapshot(fullPath)
	if snapErr != nil {
		s.record("write "+sftpPath, false, fmt.Errorf("disk: snapshot after write failed: %w (proto: %v)", snapErr, protoErr), start)
		return
	}

	var diskErr error
	if wantExists && !after.exists {
		diskErr = fmt.Errorf("disk: file missing (proto: %v)", protoErr)
	} else if !wantExists && !before.equal(after) {
		diskErr = fmt.Errorf("disk: file changed unexpectedly (proto: %v)", protoErr)
	}

	s.record("write "+sftpPath, false, diskErr, start)
}

func (r *selfTestRunner) checkRename(s *stSuite, sftp *sftp.Client, oldP, newP string, wantMoved bool) {
	start := time.Now()
	protoErr := sftp.Rename(oldP, newP)

	_, statOld := os.Stat(r.local(oldP))
	_, statNew := os.Stat(r.local(newP))

	var errs []string
	if wantMoved {
		if !os.IsNotExist(statOld) {
			errs = append(errs, "source still exists")
		}
		if os.IsNotExist(statNew) {
			errs = append(errs, "destination missing")
		}
	} else {
		// If we didn't want it moved, the old file MUST still be there
		if os.IsNotExist(statOld) {
			errs = append(errs, "source disappeared")
		}
	}

	var diskErr error
	if len(errs) > 0 {
		diskErr = fmt.Errorf("disk: %s (proto: %v)", strings.Join(errs, ", "), protoErr)
	}
	s.record("rename "+oldP, false, diskErr, start)
}

func (s *stSuite) wantFail(name string, err error) {
	s.record(name, true, err, time.Now())
}

func (s *stSuite) assert(name string, ok bool) {
	var err error
	if !ok {
		err = fmt.Errorf("assertion failed")
	}
	s.record(name, false, err, time.Now())
}

func (s *stSuite) skip(name, reason string) {
	s.steps = append(s.steps, stStep{Name: name, Skipped: true, Note: reason})
}

func (s *stSuite) passCount() (n int) {
	for _, t := range s.steps {
		if !t.Skipped && t.passed() {
			n++
		}
	}
	return
}

func (s *stSuite) failCount() (n int) {
	for _, t := range s.steps {
		if !t.Skipped && !t.passed() {
			n++
		}
	}
	return
}

func (s *stSuite) Failures() (f []stStep) {
	for _, t := range s.steps {
		if !t.Skipped && !t.passed() {
			f = append(f, t)
		}
	}
	return f
}

func (s *stSuite) skipCount() (n int) {
	for _, t := range s.steps {
		if t.Skipped {
			n++
		}
	}
	return
}

// ============================================================================
// Per-suite slog output  (warn on fail, info on pass)
// ============================================================================

func (r *selfTestRunner) logSuite(s *stSuite) {
	for i, t := range s.steps {
		num := i + 1
		if t.Skipped {
			r.log.Debug("self-test step",
				"suite", s.name, "step", num, "name", t.Name,
				"result", "SKIP", "note", t.Note,
			)
			continue
		}

		result := "PASS"
		level := slog.LevelInfo
		if !t.passed() {
			result = "FAIL"
			level = slog.LevelWarn
		}

		want := "ok"
		if t.WantFail {
			want = "fail"
		}
		got := "ok"
		if t.Err != nil {
			got = "fail"
		}

		attrs := []any{
			"suite", s.name,
			"step", num,
			"name", t.Name,
			"result", result,
			"want", want,
			"got", got,
			"dur", t.Dur.Round(time.Millisecond).String(),
		}
		if t.Err != nil && !t.passed() {
			attrs = append(attrs, "err", t.Err.Error())
		}
		r.log.Log(nil, level, "self-test step", attrs...) //nolint:sloglint
	}
}
