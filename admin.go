package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/ssh"
)

// ─────────────────────────────────────────────────────────────────────────────
// Types & Constants
// ─────────────────────────────────────────────────────────────────────────────

type tickMsg time.Time

const (
	EventAdminLogin EventKind = "admin/login"
	EventAdminBan   EventKind = "admin/ban"
	EventAdminUnban EventKind = "admin/unban"
	EventAdminPurge EventKind = "admin/purge"
)

// Regex to extract user IDs/IPs from structured log files
var (
	reUserHash = regexp.MustCompile(`id=([a-f0-9]+)`)
	reIPAddr   = regexp.MustCompile(`remote_address=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
)

// ─────────────────────────────────────────────────────────────────────────────
// Required Server/Store Methods
// ─────────────────────────────────────────────────────────────────────────────

func (s *Store) IsBanned(pubkeyHash string) bool {
	var exists bool
	s.db.QueryRow("SELECT 1 FROM shadow_banned WHERE pubkey_hash = ?", pubkeyHash).Scan(&exists)
	return exists
}

func (s *Store) IsIPBanned(ip string) bool {
	var exists bool
	s.db.QueryRow("SELECT 1 FROM ip_banned WHERE ip_address = ?", ip).Scan(&exists)
	return exists
}

func (s *Store) IsBannedByIp(remoteAddr net.Addr) bool {
	if remoteAddr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return s.IsIPBanned(remoteAddr.String())
	}
	return s.IsIPBanned(host)
}

func (s *Server) isAdminConn(permissions *ssh.Permissions) bool {
	return permissions != nil && permissions.Extensions["admin"] == "1"
}

func (s *Server) checkAdminKey(key ssh.PublicKey) bool {
	hash := fmt.Sprintf("%x", sha256.Sum256(key.Marshal()))
	return hash == s.adminHostKeyHash()
}

func (s *Server) adminHostKeyHash() string {
	keyBytes, err := os.ReadFile(s.cfg.HostKeyFile)
	if err != nil {
		return ""
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(signer.PublicKey().Marshal()))
}

func (s *Server) logAdminLogin(pubkeyHash, sessionID string, remoteAddress net.Addr) {
	s.store.LogEvent(EventAdminLogin, pubkeyHash, sessionID, remoteAddress)
}

func (s *Server) Ban(pubHash string) {
	s.store.exec("INSERT OR IGNORE INTO shadow_banned (pubkey_hash) VALUES (?)", pubHash)
}

func (s *Server) Unban(pubHash string) {
	s.store.exec("DELETE FROM shadow_banned WHERE pubkey_hash = ?", pubHash)
	s.store.exec("DELETE FROM ip_banned WHERE ip_address = ?", pubHash)
}

func (s *Server) PurgeUser(pubHash string) error {
	if pubHash == "system" || pubHash == "" {
		return nil
	}
	paths, err := s.store.FilesByOwner(pubHash)
	if err != nil {
		return err
	}
	for _, rel := range paths {
		full := filepath.Join(s.absUploadDir, filepath.FromSlash(rel))
		os.RemoveAll(full)
	}
	s.store.exec("DELETE FROM files WHERE owner_hash = ?", pubHash)
	s.store.exec("DELETE FROM shadow_banned WHERE pubkey_hash = ?", pubHash)
	_, err = s.store.exec("DELETE FROM users WHERE pubkey_hash = ?", pubHash)
	s.store.LogEvent(EventAdminPurge, systemOwner, "admin", nil, "target", pubHash)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// TUI Model & Styles
// ─────────────────────────────────────────────────────────────────────────────

var (
	styleSelected = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("6")).Bold(true)
	styleHeader   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62")).Padding(0, 1)
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleRed      = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styleGreen    = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	styleGold     = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	styleMagenta  = lipgloss.NewStyle().Foreground(lipgloss.Color("5"))
)

type activeTab int

const (
	tabStats activeTab = iota
	tabUsers
	tabFiles
	tabAudit
	tabSysLog
	maxTabs = 5
)

type adminModel struct {
	console       *adminConsole
	tab           activeTab
	table         table.Model
	filterInput   textinput.Model
	spinner       spinner.Model
	isLoading     bool
	isFiltering   bool
	inspectedUser string
	purgeConfirm  string
	width, height int
	statusMsg     string
	currentDir    string
}

type refreshMsg struct {
	tab           activeTab
	cols          []table.Column
	rows          []table.Row
	inspectedUser string
}

func initialAdminModel(a *adminConsole) adminModel {
	t := table.New(table.WithFocused(true))
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).BorderBottom(true).Bold(false)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Bold(false)
	t.SetStyles(s)
	ti := textinput.New()
	ti.Placeholder = "Search..."
	sp := spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("6"))))

	return adminModel{
		console:     a,
		tab:         tabStats,
		table:       t,
		filterInput: ti,
		spinner:     sp,
		currentDir:  ".",
		width:       80,
		height:      24,
	}
}

func (m adminModel) Init() tea.Cmd {
	return tea.Batch(m.refreshData(), m.spinner.Tick, m.tick())
}

func (m adminModel) tick() tea.Cmd {
	return tea.Tick(time.Second*5, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// ─────────────────────────────────────────────────────────────────────────────
// Data Refresh Logic
// ─────────────────────────────────────────────────────────────────────────────

func (m adminModel) refreshData() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()

		var cols []table.Column
		var rows []table.Row
		s := m.console.srv.store
		f := "%" + m.filterInput.Value() + "%"
		w := m.width
		if w <= 0 {
			w = 80
		}

		if m.inspectedUser != "" {
			cols = []table.Column{{Title: "Owned Path", Width: w - 25}, {Title: "Size", Width: 15}}
			q := "SELECT path, size, is_dir FROM files WHERE owner_hash = ? ORDER BY path ASC"
			dbRows, _ := s.db.QueryContext(ctx, q, m.inspectedUser)
			if dbRows != nil {
				defer dbRows.Close()
				for dbRows.Next() {
					var p string
					var sz int64
					var isDir bool
					if err := dbRows.Scan(&p, &sz, &isDir); err == nil {
						txt := p
						if isDir {
							txt = styleMagenta.Render(p + "/")
						}
						rows = append(rows, table.Row{txt, formatBytes(sz)})
					}
				}
			}
			return refreshMsg{tab: m.tab, cols: cols, rows: rows, inspectedUser: m.inspectedUser}
		}

		switch m.tab {
		case tabStats:
			cols = []table.Column{{Title: "Metric", Width: 20}, {Title: "Value", Width: w - 25}}
			u, c, f, b := s.GetBannerStats(m.console.srv.cfg.ContributorThreshold)
			rows = []table.Row{
				{"Archive", m.console.srv.cfg.Name},
				{"Users", fmt.Sprintf("%d", u)},
				{"Contribs", fmt.Sprintf("%d", c)},
				{"Files", fmt.Sprintf("%d", f)},
				{"Total Disk", formatBytes(int64(b))},
			}
		case tabUsers:
			cols = []table.Column{{Title: "User Pubkey Hash", Width: w - 45}, {Title: "Shared", Width: 15}, {Title: "Status", Width: 10}}
			q := "SELECT pubkey_hash, upload_bytes FROM users WHERE pubkey_hash != 'system' AND pubkey_hash LIKE ? ORDER BY upload_bytes DESC"
			dbRows, _ := s.db.QueryContext(ctx, q, f)
			if dbRows != nil {
				defer dbRows.Close()
				for dbRows.Next() {
					var h string
					var ub int64
					if err := dbRows.Scan(&h, &ub); err == nil {
						stat := styleGreen.Render("Active")
						if s.IsBanned(h) {
							stat = styleRed.Render("Banned")
						}
						rows = append(rows, table.Row{h, formatBytes(ub), stat})
					}
				}
			}
		case tabFiles:
			cols = []table.Column{{Title: "Filename", Width: w - 40}, {Title: "Owner", Width: 15}, {Title: "Size", Width: 10}}
			abs := filepath.Join(m.console.srv.absUploadDir, filepath.FromSlash(m.currentDir))
			entries, _ := os.ReadDir(abs)
			for _, e := range entries {
				fi, _ := e.Info()
				name := e.Name()
				if e.IsDir() {
					name = styleGold.Render(name + "/")
				}
				rel := filepath.ToSlash(filepath.Join(m.currentDir, e.Name()))
				owner, _ := s.GetFileOwner(rel)
				rows = append(rows, table.Row{name, shortID(owner), formatBytes(fi.Size())})
			}
		case tabAudit:
			cols = []table.Column{{Title: "Time", Width: 10}, {Title: "Event", Width: 12}, {Title: "User", Width: 12}, {Title: "Details", Width: w - 40}}
			q := `SELECT timestamp, event, IFNULL(user_id, ''), IFNULL(path, '') || ' ' || IFNULL(meta, '') FROM log 
			      WHERE (user_id LIKE ? OR event LIKE ? OR path LIKE ?) ORDER BY timestamp DESC LIMIT 50`
			dbRows, _ := s.db.QueryContext(ctx, q, f, f, f)
			if dbRows != nil {
				defer dbRows.Close()
				for dbRows.Next() {
					var ts int64
					var ev, u, det string
					if err := dbRows.Scan(&ts, &ev, &u, &det); err == nil {
						rows = append(rows, table.Row{time.Unix(ts, 0).Format("15:04"), ev, shortID(u), det})
					}
				}
			}
		case tabSysLog:
			cols = []table.Column{{Title: "System Log File Tail (Last 100 lines)", Width: w - 5}}
			file, err := os.Open(m.console.srv.cfg.LogFile)
			if err == nil {
				defer file.Close()
				var lines []string
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					txt := scanner.Text()
					if m.filterInput.Value() == "" || strings.Contains(txt, m.filterInput.Value()) {
						lines = append(lines, txt)
					}
				}
				// Take last 100
				start := 0
				if len(lines) > 100 {
					start = len(lines) - 100
				}
				for i := len(lines) - 1; i >= start; i-- {
					rows = append(rows, table.Row{lines[i]})
				}
			}
		}
		return refreshMsg{tab: m.tab, cols: cols, rows: rows}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Update Logic
// ─────────────────────────────────────────────────────────────────────────────

func (m adminModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.table.SetWidth(m.width - 4)
		m.table.SetHeight(m.height - 10)
		return m, m.refreshData()
	case tickMsg:
		if !m.isFiltering && !m.isLoading {
			return m, tea.Batch(m.refreshData(), m.tick())
		}
		return m, m.tick()
	case refreshMsg:
		m.isLoading = false
		m.table.SetRows([]table.Row{}) // Clear to avoid index panic
		m.table.SetColumns(msg.cols)
		m.table.SetRows(msg.rows)
		return m, nil

	case tea.KeyMsg:
		if m.purgeConfirm != "" {
			switch msg.String() {
			case "y":
				m.console.srv.PurgeUser(m.purgeConfirm)
				m.statusMsg = "PURGED: " + shortID(m.purgeConfirm)
				m.purgeConfirm = ""
				return m, m.refreshData()
			default:
				m.purgeConfirm = ""
				return m, nil
			}
		}
		if m.isFiltering {
			if msg.String() == "enter" || msg.String() == "esc" {
				m.isFiltering = false
				m.filterInput.Blur()
				return m, m.refreshData()
			}
			m.filterInput, cmd = m.filterInput.Update(msg)
			return m, cmd
		}
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab":
			if m.inspectedUser == "" {
				m.tab = (m.tab + 1) % maxTabs
				m.table.SetRows([]table.Row{})
				m.isLoading = true
				return m, m.refreshData()
			}
		case "/":
			m.isFiltering = true
			m.filterInput.Focus()
			return m, nil
		case "r":
			m.isLoading = true
			return m, m.refreshData()
		case "esc", "backspace":
			if m.inspectedUser != "" {
				m.inspectedUser = ""
				return m, m.refreshData()
			}
			if m.tab == tabFiles && m.currentDir != "." {
				m.currentDir = filepath.Dir(m.currentDir)
				return m, m.refreshData()
			}
		case "i": // Inspect
			var target string
			if m.tab == tabUsers && len(m.table.Rows()) > 0 {
				target = m.table.SelectedRow()[0]
			} else if m.tab == tabFiles && len(m.table.Rows()) > 0 {
				rel := filepath.ToSlash(filepath.Join(m.currentDir, stripANSI(m.table.SelectedRow()[0])))
				target, _ = m.console.srv.store.GetFileOwner(rel)
			} else if m.tab == tabSysLog && len(m.table.Rows()) > 0 {
				match := reUserHash.FindStringSubmatch(m.table.SelectedRow()[0])
				if len(match) > 1 {
					target = match[1]
				}
			}
			if target != "" && target != "system" {
				m.inspectedUser = target
				m.isLoading = true
				return m, m.refreshData()
			}
		case "b": // Ban (from Users or SysLog)
			target := ""
			if m.tab == tabUsers && len(m.table.Rows()) > 0 {
				target = m.table.SelectedRow()[0]
			} else if m.tab == tabSysLog && len(m.table.Rows()) > 0 {
				row := m.table.SelectedRow()[0]
				matchH := reUserHash.FindStringSubmatch(row)
				if len(matchH) > 1 {
					target = matchH[1]
				} else {
					matchI := reIPAddr.FindStringSubmatch(row)
					if len(matchI) > 1 {
						m.console.srv.store.exec("INSERT OR IGNORE INTO ip_banned (ip_address) VALUES (?)", matchI[1])
					}
				}
			}
			if target != "" {
				m.console.srv.Ban(target)
				return m, m.refreshData()
			}
		case "u":
			if m.tab == tabUsers && len(m.table.Rows()) > 0 {
				m.console.srv.Unban(m.table.SelectedRow()[0])
				return m, m.refreshData()
			}
		case "p": // Purge
			if m.tab == tabUsers && len(m.table.Rows()) > 0 {
				m.purgeConfirm = m.table.SelectedRow()[0]
				return m, nil
			}
		case "enter":
			if m.tab == tabFiles && len(m.table.Rows()) > 0 {
				sel := stripANSI(m.table.SelectedRow()[0])
				if strings.HasSuffix(sel, "/") {
					m.currentDir = filepath.Join(m.currentDir, strings.TrimSuffix(sel, "/"))
					m.table.SetCursor(0)
					return m, m.refreshData()
				}
			}
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

// ─────────────────────────────────────────────────────────────────────────────
// View
// ─────────────────────────────────────────────────────────────────────────────

func (m adminModel) View() string {
	spin := ""
	if m.isLoading {
		spin = " " + m.spinner.View()
	}
	header := styleHeader.Render(fmt.Sprintf(" %s ADMIN ", strings.ToUpper(m.console.srv.cfg.Name)) + spin)

	tabNames := []string{"Stats", "Users", "Files", "User Audit", "SysLogs"}
	var tabs []string
	for i, n := range tabNames {
		if activeTab(i) == m.tab && m.inspectedUser == "" {
			tabs = append(tabs, styleSelected.Render(" "+n+" "))
		} else {
			tabs = append(tabs, styleDim.Render(" "+n+" "))
		}
	}

	bar := styleGold.Render(" 📂 " + m.currentDir)
	if m.inspectedUser != "" {
		bar = styleMagenta.Render(" 🔍 INSPECTING: " + m.inspectedUser)
	} else if m.purgeConfirm != "" {
		bar = styleRed.Bold(true).Render(" ⚠️  PURGE USER " + shortID(m.purgeConfirm) + "? (y/n)")
	} else if m.statusMsg != "" {
		bar = styleGreen.Render(" ✨ " + m.statusMsg)
	}

	help := " tab: cycle • /: search • r: refresh • q: quit"
	if m.inspectedUser != "" {
		help = " esc: back • r: refresh"
	} else if m.tab == tabUsers {
		help = " i: inspect • p: purge • b: ban • u: unban"
	} else if m.tab == tabFiles {
		help = " enter: cd • backspace: up • i: inspect owner"
	} else if m.tab == tabSysLog {
		help = " i: inspect row user • b: ban row user/ip"
	}

	body := m.table.View()
	if m.isFiltering {
		body += "\n" + m.filterInput.View()
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, lipgloss.JoinHorizontal(lipgloss.Top, tabs...), bar, "", body, styleDim.Render("\n "+help))
}

func stripANSI(s string) string {
	return regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`).ReplaceAllString(s, "")
}

// ─────────────────────────────────────────────────────────────────────────────
// SSH Glue
// ─────────────────────────────────────────────────────────────────────────────

type adminConsole struct {
	srv    *Server
	ch     ssh.Channel
	sid    string
	hasPTY bool
}

func (s *Server) handleAdminChannel(ch ssh.Channel, reqs <-chan *ssh.Request, sid string) {
	defer ch.Close()
	c := &adminConsole{srv: s, ch: ch, sid: sid}
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			c.hasPTY = true
			r.Reply(true, nil)
		case "shell":
			r.Reply(true, nil)
			c.run()
			return
		default:
			r.Reply(false, nil)
		}
	}
}
func (a *adminConsole) run() {
	if !a.hasPTY {
		io.WriteString(a.ch, "PTY required\n")
		return
	}
	p := tea.NewProgram(initialAdminModel(a), tea.WithInput(a.ch), tea.WithOutput(a.ch), tea.WithAltScreen())
	p.Run()
}
