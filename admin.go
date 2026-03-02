package main

/*
admin.go — Interactive admin console for sftpguy

When a connecting client authenticates with a key whose public key fingerprint
matches the server's own host key, they are routed here instead of the normal
SFTP subsystem.  The console runs over the SSH channel as an interactive
terminal using the Charmbracelet TUI stack (Bubble Tea + Lip Gloss + Bubbles).

TUI framework
─────────────
  • Bubble Tea (github.com/charmbracelet/bubbletea) — the Elm-architecture
    event loop.  The program is wired directly to the SSH channel via
    tea.WithInput / tea.WithOutput, so it works with any ssh client that
    requests a PTY ("ssh -t host").
  • Lip Gloss (github.com/charmbracelet/lipgloss) — all colour/style
    declarations.  Replaces the old hand-rolled asciiStyle system.
  • Bubbles textinput (github.com/charmbracelet/bubbles/textinput) — gives
    the prompt full readline-style editing and command history for free.
  • Bubbles viewport — scrollable output region shared by the main console
    and the three panel modes (log viewer, DB viewer, file browser).
  • Bubbles table — used for the DB viewer panel.

Panel modes
───────────
  Three full-screen panels can be launched from the REPL:
    view-logs  [n]               — scrollable, colour-coded log stream
    view-db    <table>           — paginated table view (users/files/log/bans)
    view-files [path]            — interactive file browser with preview

  Inside a panel: ↑/↓ to scroll, PgUp/PgDn for page jumps, q/Esc to return.
  In view-files: Enter opens a directory; backspace/h goes up; p previews a file.

No-PTY fallback
───────────────
  If the client does not request a PTY (plain "ssh host" without -t), bubbletea
  cannot render a real TUI.  In that case Run() falls back to the original
  line-oriented REPL, which still uses Lip Gloss for colour but writes
  directly to the channel with CRLF line endings.

Security model
──────────────
  • Identity check happens in publicKeyCallback - if the fingerprint of the
    connecting public key equals the fingerprint of our own host key we set
    the extension "admin" = "1" in the Permissions map.
  • handleChannel checks that extension before launching any shell/subsystem.
  • No password escalation is possible; only the holder of the private key
    that matches the server's own key gets in.
  • All admin commands are logged to the structured logger AND to the DB log
    table with a new EventAdmin kind.

IP bans vs shadow bans
──────────────────────
  ip-ban / ip-unban shadow-ban the IP rather than hard-dropping the connection.
  Hard drops are trivially detected; shadow banning makes it look normal from
  the outside while being useless to the attacker.

Navigation
──────────
  The admin console tracks a working directory (cwd) relative to the upload
  root.  pwd and cd are supported.  All path arguments are resolved relative
  to the cwd.  The user can never escape the upload root.
*/

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/ssh"
)

// EventAdmin is the log kind used for all admin-console actions.
const (
	EventAdminLogin EventKind = "admin_login"
	EventAdmin      EventKind = "admin"
)

// ─────────────────────────────────────────────────────────────────────────────
// Lip Gloss styles — replacing the old asciiStyle constants
// ─────────────────────────────────────────────────────────────────────────────

var (
	styleRed       = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styleGreen     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	styleYellow    = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	styleBlue      = lipgloss.NewStyle().Foreground(lipgloss.Color("4"))
	styleCyan      = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	styleWhite     = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	styleDarkGray  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleLightGray = lipgloss.NewStyle().Foreground(lipgloss.Color("7"))

	styleRedBold    = styleRed.Bold(true)
	styleGreenBold  = styleGreen.Bold(true)
	styleYellowBold = styleYellow.Bold(true)
	styleWhiteBold  = styleWhite.Bold(true)
	styleCyanBold   = styleCyan.Bold(true)
	styleBlueBold   = styleBlue.Bold(true)

	// ── Layout styles ──────────────────────────────────────────────────────

	styleHeaderBar = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("1")).
			Padding(0, 1)

	styleFooterBar = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			Background(lipgloss.Color("0")).
			Padding(0, 1)

	styleViewportBorder = lipgloss.NewStyle().
				Foreground(lipgloss.Color("8"))

	styleBanner = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("1")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("1")).
			Padding(0, 2)

	// Panel-specific
	stylePanelHeader = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("15")).
				Background(lipgloss.Color("4")).
				Padding(0, 1)

	stylePanelFooter = lipgloss.NewStyle().
				Foreground(lipgloss.Color("8")).
				Background(lipgloss.Color("0")).
				Padding(0, 1)

	styleSelected = lipgloss.NewStyle().
			Foreground(lipgloss.Color("0")).
			Background(lipgloss.Color("6")).
			Bold(true)

	styleDir     = lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	styleFile    = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	styleSysFile = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
)

// ─────────────────────────────────────────────────────────────────────────────
// AdminCommand — self-describing command descriptor
// ─────────────────────────────────────────────────────────────────────────────

// AdminCommand describes a single admin console command.
type AdminCommand struct {
	Name     string
	Aliases  []string
	Usage    string
	Help     string
	Category string
	// Handler runs the command and appends output to out.
	// Returning true signals the REPL / TUI to end the session.
	Handler func(args []string, out *strings.Builder) (exit bool)
}

// ─────────────────────────────────────────────────────────────────────────────
// adminConsole — shared state used by both TUI and fallback REPL
// ─────────────────────────────────────────────────────────────────────────────

type adminConsole struct {
	srv       *Server
	ch        ssh.Channel
	logger    *slog.Logger
	sessionID string
	cwd       string // relative to absUploadDir; "" means root

	registry []AdminCommand
	byName   map[string]*AdminCommand

	// hasPTY is set by handleAdminChannel when the client sends a pty-req.
	hasPTY bool
}

func newAdminConsole(srv *Server, ch ssh.Channel, sessionID string) *adminConsole {
	a := &adminConsole{
		srv:       srv,
		ch:        ch,
		logger:    srv.logger.WithGroup("admin"),
		sessionID: sessionID,
		cwd:       "",
	}
	a.buildRegistry()
	return a
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) buildRegistry() {
	a.registry = []AdminCommand{
		// ── Files ────────────────────────────────────────────────────────
		{Name: "ls", Usage: "ls [path]", Help: "List directory contents",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdLs(args, out); return false }},
		{Name: "pwd", Usage: "pwd", Help: "Show current working directory",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdPwd(out); return false }},
		{Name: "cd", Usage: "cd [path]", Help: "Change working directory (confined to upload root)",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdCd(args, out); return false }},
		{Name: "cat", Usage: "cat <path>", Help: "Print file contents",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdCat(args, out); return false }},
		{Name: "rm", Usage: "rm <path>", Help: "Delete file or directory tree",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdRm(args, out); return false }},
		{Name: "mv", Usage: "mv <src> <dst>", Help: "Move/rename",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdMv(args, out); return false }},
		{Name: "chown", Usage: "chown <hash> <path>", Help: "Re-assign file ownership to user hash",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdChown(args, out); return false }},
		{Name: "protect", Usage: "protect <path>", Help: "Mark path as system-owned (undeletable by users)",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdProtect(args, true, out); return false }},
		{Name: "unprotect", Usage: "unprotect <path>", Help: "Remove system ownership",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdProtect(args, false, out); return false }},
		{Name: "unrestrict", Usage: "unrestrict <path>", Help: "Add path to unrestricted download list (runtime only)",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdUnrestrict(args, true, out); return false }},
		{Name: "restrict", Usage: "restrict <path>", Help: "Remove path from unrestricted download list",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdUnrestrict(args, false, out); return false }},
		{Name: "inspect", Aliases: []string{"i"}, Usage: "inspect [path]", Help: "Show file/directory metadata",
			Category: "Files",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdInspect(args, out); return false }},

		// ── Interactive Viewers ───────────────────────────────────────────
		{Name: "view-logs", Aliases: []string{"vl"}, Usage: "view-logs [n]", Help: "Interactive log viewer (↑↓ PgUp/PgDn, q=back)",
			Category: "Viewers",
			Handler: func(args []string, out *strings.Builder) bool {
				if a.hasPTY {
					a.runLogViewer(args)
				} else {
					a.cmdLogs(args, "", "", "", out)
				}
				return false
			}},
		{Name: "view-db", Aliases: []string{"vd"}, Usage: "view-db <users|files|log|bans>", Help: "Interactive DB table viewer (↑↓ PgUp/PgDn, q=back)",
			Category: "Viewers",
			Handler: func(args []string, out *strings.Builder) bool {
				if a.hasPTY {
					a.runDBViewer(args)
				} else {
					writef(out, styleYellow, "view-db requires a PTY. Connect with: ssh -t host\n")
				}
				return false
			}},
		{Name: "view-files", Aliases: []string{"vf"}, Usage: "view-files [path]", Help: "Interactive file browser (Enter=open, p=preview, q=back)",
			Category: "Viewers",
			Handler: func(args []string, out *strings.Builder) bool {
				if a.hasPTY {
					a.runFileBrowser(args)
				} else {
					a.cmdLs(args, out)
				}
				return false
			}},

		// ── Users ────────────────────────────────────────────────────────
		{Name: "users", Usage: "users", Help: "List all known users",
			Category: "Users",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdUsers(out); return false }},
		{Name: "user", Usage: "user <hash>", Help: "Show stats for a user (prefix match OK)",
			Category: "Users",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdUser(args, out); return false }},
		{Name: "ban", Usage: "ban <hash|path>", Help: "Shadow-ban a user by hash, or by path (bans the file's owner)",
			Category: "Users",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdBan(args, true, out); return false }},
		{Name: "unban", Usage: "unban <hash>", Help: "Remove shadow-ban",
			Category: "Users",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdBan(args, false, out); return false }},
		{Name: "purge", Usage: "purge <hash>", Help: "Delete all files owned by user (prompts for confirmation)",
			Category: "Users",
			Handler:  func(args []string, out *strings.Builder) bool { return a.cmdPurge(args, out) }},

		// ── IP / Network ─────────────────────────────────────────────────
		{Name: "ip-ban", Usage: "ip-ban <ip>", Help: "Shadow-ban an IP address",
			Category: "IP / Network",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdIPBan(args, true, out); return false }},
		{Name: "ip-unban", Usage: "ip-unban <ip>", Help: "Remove IP shadow-ban",
			Category: "IP / Network",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdIPBan(args, false, out); return false }},
		{Name: "ip-list", Usage: "ip-list", Help: "List all banned IPs",
			Category: "IP / Network",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdIPList(out); return false }},

		// ── Logs ─────────────────────────────────────────────────────────
		{Name: "logs", Usage: "logs [n]", Help: "Last n log entries (default 50)",
			Category: "Logs",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdLogs(args, "", "", "", out); return false }},
		{Name: "logs-user", Usage: "logs-user <hash> [n]", Help: "Logs for a specific user",
			Category: "Logs",
			Handler: func(args []string, out *strings.Builder) bool {
				if len(args) == 0 {
					writef(out, styleRed, "Usage: logs-user <hash> [n]\n")
				} else {
					a.cmdLogs(args[1:], args[0], "", "", out)
				}
				return false
			}},
		{Name: "logs-event", Usage: "logs-event <kind> [n]", Help: "Logs for an event kind (login/upload/download/…)",
			Category: "Logs",
			Handler: func(args []string, out *strings.Builder) bool {
				if len(args) == 0 {
					writef(out, styleRed, "Usage: logs-event <kind> [n]\n")
				} else {
					a.cmdLogs(args[1:], "", args[0], "", out)
				}
				return false
			}},
		{Name: "logs-ip", Usage: "logs-ip <ip> [n]", Help: "Logs for a specific IP",
			Category: "Logs",
			Handler: func(args []string, out *strings.Builder) bool {
				if len(args) == 0 {
					writef(out, styleRed, "Usage: logs-ip <ip> [n]\n")
				} else {
					a.cmdLogs(args[1:], "", "", args[0], out)
				}
				return false
			}},

		// ── Stats ────────────────────────────────────────────────────────
		{Name: "stats", Usage: "stats", Help: "Overall server statistics",
			Category: "Stats",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdStats(out); return false }},
		{Name: "top-uploaders", Usage: "top-uploaders [n]", Help: "Top n uploaders by bytes",
			Category: "Stats",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdTopUsers(args, "upload", out); return false }},
		{Name: "top-downloaders", Usage: "top-downloaders [n]", Help: "Top n downloaders by bytes",
			Category: "Stats",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdTopUsers(args, "download", out); return false }},

		// ── Server ───────────────────────────────────────────────────────
		{Name: "config", Usage: "config", Help: "Show running configuration",
			Category: "Server",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdConfig(out); return false }},
		{Name: "reload-banner", Usage: "reload-banner", Help: "Reload banner file from disk",
			Category: "Server",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdReloadBanner(out); return false }},
		{Name: "shutdown", Usage: "shutdown", Help: "Graceful shutdown (prompts for confirmation)",
			Category: "Server",
			Handler:  func(args []string, out *strings.Builder) bool { return a.cmdShutdown(out) }},

		// ── Misc ─────────────────────────────────────────────────────────
		{Name: "whoami", Usage: "whoami", Help: "Confirm admin identity",
			Category: "Misc",
			Handler: func(args []string, out *strings.Builder) bool {
				out.WriteString(styleWhiteBold.Render("You are the server administrator.") + "\n")
				return false
			}},
		{Name: "fortune", Usage: "fortune", Help: "Today will be a good day.",
			Category: "Misc",
			Handler: func(args []string, out *strings.Builder) bool {
				out.WriteString(styleWhiteBold.Render(a.srv.getRandomFortune()) + "\n")
				return false
			}},
		{Name: "help", Aliases: []string{"?"}, Usage: "help [command]", Help: "Show this list, or detail for one command",
			Category: "Misc",
			Handler:  func(args []string, out *strings.Builder) bool { a.cmdHelp(args, out); return false }},
		{Name: "exit", Aliases: []string{"quit", "q"}, Usage: "exit", Help: "Close session",
			Category: "Misc",
			Handler:  func(args []string, out *strings.Builder) bool { return true }},
	}

	a.byName = make(map[string]*AdminCommand, len(a.registry)*2)
	for i := range a.registry {
		c := &a.registry[i]
		a.byName[c.Name] = c
		for _, alias := range c.Aliases {
			a.byName[alias] = c
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// dispatch — shared by both TUI and fallback REPL
// ─────────────────────────────────────────────────────────────────────────────

// dispatch runs the named command and returns (output, exit).
func (a *adminConsole) dispatch(cmd string, args []string) (string, bool) {
	c, ok := a.byName[cmd]
	if !ok {
		var out strings.Builder
		writef(&out, styleRed, "Unknown command: %q  (type \"help\" for list)\n", cmd)
		return out.String(), false
	}
	var out strings.Builder
	exit := c.Handler(args, &out)
	return out.String(), exit
}

// ─────────────────────────────────────────────────────────────────────────────
// Run — entry point; chooses TUI or fallback REPL
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) Run() {
	a.srv.store.LogEvent(EventAdminLogin, "admin", a.sessionID, nil, "action", "login")

	if a.hasPTY {
		a.runTUI()
	} else {
		a.runREPL()
	}

	a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", "logout")
}

// ─────────────────────────────────────────────────────────────────────────────
// Bubble Tea TUI (PTY path)
// ─────────────────────────────────────────────────────────────────────────────

// adminModel is the Bubble Tea model.
type adminModel struct {
	console *adminConsole
	input   textinput.Model
	vp      viewport.Model
	spin    spinner.Model
	history []string
	histIdx int
	width   int
	height  int
	ready   bool // true once first WindowSizeMsg received
	busy    bool // true while async command runs

	scrollback []string // every line ever written; viewport is rebuilt from this

	// confirmCmd holds a pending destructive command waiting for user input.
	confirmCmd *pendingConfirm

	// Autocomplete state
	completions []string
	compIdx     int
}

// pendingConfirm represents a two-step confirmation prompt (purge, shutdown).
type pendingConfirm struct {
	prompt     string
	shouldQuit bool
	onInput    func(answer string) string
}

// cmdDoneMsg is sent when an async command finishes.
type cmdDoneMsg struct {
	output string
	exit   bool
}

// ── Layout constants ─────────────────────────────────────────────────────────

const (
	tuiHeaderHeight    = 1 // top bar
	tuiFooterHeight    = 1 // bottom status strip
	tuiSeparatorHeight = 1 // line between viewport and prompt
	tuiPromptHeight    = 1 // prompt + input line
)

// ── appendOutput & viewport rebuild ─────────────────────────────────────────

func (m *adminModel) appendOutput(s string) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	m.scrollback = append(m.scrollback, lines...)
	if m.ready {
		m.vp.SetContent(strings.Join(m.scrollback, "\n"))
		m.vp.GotoBottom()
	}
}

// ── Initialisation ───────────────────────────────────────────────────────────

func initialAdminModel(a *adminConsole) adminModel {
	ti := textinput.New()
	ti.Placeholder = "type a command…"
	ti.Focus()
	ti.CharLimit = 1024

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))

	m := adminModel{
		console: a,
		input:   ti,
		spin:    sp,
		histIdx: -1,
		compIdx: -1,
	}

	now := time.Now()
	var sb strings.Builder
	sb.WriteString(styleBanner.Render("  sftpguy  ADMIN  CONSOLE  ") + "\n")
	sb.WriteString(styleDarkGray.Render(fmt.Sprintf(
		"Session %-16s   Connected %s",
		a.sessionID[:16], now.Format("2006-01-02 15:04:05 MST"))) + "\n")
	sb.WriteString(hrLine(72) + "\n")
	sb.WriteString(styleCyan.Render(`Type "help" for commands · Tab to autocomplete · PgUp/PgDn to scroll`) + "\n")
	sb.WriteString(styleDarkGray.Render(`Viewers: view-logs (vl) · view-db (vd) · view-files (vf)`) + "\n")
	m.appendOutput(sb.String())
	return m
}

func (m adminModel) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, tea.EnterAltScreen)
}

// ── Update ───────────────────────────────────────────────────────────────────

func (m adminModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Extra line below viewport when confirm/completions hint is visible.
		extra := 0
		if m.confirmCmd != nil || len(m.completions) > 1 {
			extra = 1
		}
		vpH := m.height - tuiHeaderHeight - tuiFooterHeight - tuiSeparatorHeight - tuiPromptHeight - extra
		if vpH < 1 {
			vpH = 1
		}

		if !m.ready {
			m.vp = viewport.New(m.width, vpH)
			m.ready = true
			m.vp.SetContent(strings.Join(m.scrollback, "\n"))
			m.vp.GotoBottom()
		} else {
			m.vp.Width = m.width
			m.vp.Height = vpH
		}
		m.input.Width = m.width - 22
		return m, nil

	case cmdDoneMsg:
		m.busy = false
		m.appendOutput(msg.output)
		if msg.exit {
			return m, tea.Sequence(tea.ExitAltScreen, tea.Quit)
		}
		return m, nil

	case spinner.TickMsg:
		if m.busy {
			var sc tea.Cmd
			m.spin, sc = m.spin.Update(msg)
			cmds = append(cmds, sc)
		}

	case tea.KeyMsg:
		if m.busy {
			return m, tea.Batch(cmds...)
		}
		if m.confirmCmd != nil {
			return m.handleConfirm(msg)
		}

		if msg.Type != tea.KeyTab {
			m.completions = nil
			m.compIdx = -1
		}

		switch msg.Type {
		case tea.KeyEnter:
			raw := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			m.histIdx = -1
			if raw == "" {
				return m, tea.Batch(cmds...)
			}
			if len(m.history) == 0 || m.history[len(m.history)-1] != raw {
				m.history = append(m.history, raw)
			}

			parts := strings.Fields(raw)
			cmd := strings.ToLower(parts[0])
			args := parts[1:]

			m.console.logger.Info("admin command", "cmd", cmd, "args", args,
				"session", m.console.sessionID[:16])
			m.console.srv.store.LogEvent(EventAdmin, "admin", m.console.sessionID, nil,
				"action", "command", "cmd", cmd)

			echo := styleRedBold.Render("admin") +
				styleDarkGray.Render("@") +
				styleYellow.Render(m.console.srv.cfg.Name) +
				" " + styleDarkGray.Render(m.console.cwdDisplay()) +
				" " + styleCyanBold.Render("» ") +
				styleWhite.Render(raw)
			m.appendOutput(echo + "\n")

			if cmd == "purge" || cmd == "shutdown" {
				return m.startConfirm(cmd, args)
			}

			m.busy = true
			console := m.console
			cmds = append(cmds,
				func() tea.Msg {
					output, exit := console.dispatch(cmd, args)
					return cmdDoneMsg{output: output, exit: exit}
				},
				m.spin.Tick,
			)
			return m, tea.Batch(cmds...)

		case tea.KeyTab:
			m.completions, m.compIdx = m.console.complete(m.input.Value(), m.completions, m.compIdx)
			if len(m.completions) == 1 {
				m.input.SetValue(m.completions[0])
				m.input.CursorEnd()
				m.completions = nil
				m.compIdx = -1
			} else if len(m.completions) > 1 {
				m.input.SetValue(m.completions[m.compIdx])
				m.input.CursorEnd()
			}
			return m, tea.Batch(cmds...)

		case tea.KeyUp:
			if len(m.history) > 0 {
				if m.histIdx == -1 {
					m.histIdx = len(m.history) - 1
				} else if m.histIdx > 0 {
					m.histIdx--
				}
				m.input.SetValue(m.history[m.histIdx])
				m.input.CursorEnd()
			}
			return m, tea.Batch(cmds...)

		case tea.KeyDown:
			if m.histIdx != -1 {
				m.histIdx++
				if m.histIdx >= len(m.history) {
					m.histIdx = -1
					m.input.SetValue("")
				} else {
					m.input.SetValue(m.history[m.histIdx])
					m.input.CursorEnd()
				}
			}
			return m, tea.Batch(cmds...)

		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Sequence(tea.ExitAltScreen, tea.Quit)

		// PgUp / PgDn / Home / End scroll the viewport.
		case tea.KeyPgUp, tea.KeyPgDown, tea.KeyHome, tea.KeyEnd:
			var vc tea.Cmd
			m.vp, vc = m.vp.Update(msg)
			return m, vc
		}
	}

	// Forward remaining events to viewport and input.
	var vc, ic tea.Cmd
	m.vp, vc = m.vp.Update(msg)
	m.input, ic = m.input.Update(msg)
	return m, tea.Batch(append(cmds, vc, ic)...)
}

// ── View ─────────────────────────────────────────────────────────────────────

func (m adminModel) View() string {
	if !m.ready {
		return ""
	}
	w := m.width

	rightStr := m.console.srv.cfg.Name + "  ·  " + m.console.cwdDisplay() + "  ·  " + time.Now().Format("15:04:05")
	leftStr := "sftpguy ADMIN"
	gapWidth := w - lipgloss.Width(leftStr) - lipgloss.Width(rightStr)
	if gapWidth < 1 {
		gapWidth = 1
	}
	header := styleHeaderBar.Copy().Width(w).Render(
		leftStr + strings.Repeat(" ", gapWidth) + rightStr,
	)

	vpView := m.vp.View()

	separator := styleViewportBorder.Render(strings.Repeat("─", w))

	var promptLine string
	if m.busy {
		promptLine = m.spin.View() + " " + styleDarkGray.Render("running…")
	} else {
		promptLine = styleRedBold.Render("admin") +
			styleDarkGray.Render("@") +
			styleYellow.Render(m.console.srv.cfg.Name) +
			" " + styleDarkGray.Render(m.console.cwdDisplay()) +
			" " + styleCyanBold.Render("» ") +
			m.input.View()
	}

	var extraLine string
	switch {
	case m.confirmCmd != nil:
		extraLine = "\n" + styleYellowBold.Render("  "+m.confirmCmd.prompt)
	case len(m.completions) > 1:
		var parts []string
		for i, c := range m.completions {
			display := c
			if idx := strings.LastIndexAny(c, "/ "); idx >= 0 && idx < len(c)-1 {
				display = c[idx+1:]
			}
			if i == m.compIdx {
				parts = append(parts, styleWhiteBold.Render(display))
			} else {
				parts = append(parts, styleDarkGray.Render(display))
			}
		}
		extraLine = "\n  " + strings.Join(parts, styleDarkGray.Render("  ·  "))
	}

	pctStr := "100%"
	if !m.vp.AtBottom() {
		pctStr = fmt.Sprintf("%d%%", int(m.vp.ScrollPercent()*100))
	}
	footerLeft := fmt.Sprintf("  %d lines", len(m.scrollback))
	footerRight := fmt.Sprintf("PgUp/PgDn to scroll · %s  ", pctStr)
	fgap := w - lipgloss.Width(footerLeft) - lipgloss.Width(footerRight)
	if fgap < 0 {
		fgap = 0
	}
	footer := styleFooterBar.Copy().Width(w).Render(
		footerLeft + strings.Repeat(" ", fgap) + footerRight,
	)

	return strings.Join([]string{
		header,
		vpView,
		separator,
		promptLine + extraLine,
		footer,
	}, "\n")
}

// ── handleConfirm ────────────────────────────────────────────────────────────

func (m adminModel) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type != tea.KeyEnter {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	answer := strings.TrimSpace(m.input.Value())
	m.input.SetValue("")

	pending := m.confirmCmd
	m.confirmCmd = nil
	output := pending.onInput(answer)
	m.appendOutput(output)

	if pending.shouldQuit {
		return m, tea.Sequence(tea.ExitAltScreen, tea.Quit)
	}
	return m, nil
}

// ── startConfirm ─────────────────────────────────────────────────────────────

func (m adminModel) startConfirm(cmd string, args []string) (adminModel, tea.Cmd) {
	switch cmd {
	case "shutdown":
		m.appendOutput(styleRedBold.Render("WARNING: This will shut down the server for ALL users.") + "\n")
		pending := &pendingConfirm{
			prompt: `Type "SHUTDOWN" to confirm, or anything else to cancel: `,
		}
		pending.onInput = func(answer string) string {
			if answer != "SHUTDOWN" {
				return styleYellow.Render("Cancelled.") + "\n"
			}
			pending.shouldQuit = true
			m.console.srv.store.LogEvent(EventAdmin, "admin", m.console.sessionID, nil, "action", "shutdown")
			go m.console.srv.Shutdown()
			return styleRedBold.Render("Shutting down…") + "\n"
		}
		m.confirmCmd = pending

	case "purge":
		var sb strings.Builder
		if len(args) == 0 {
			writef(&sb, styleRed, "Usage: purge <hash>\n")
			m.appendOutput(sb.String())
			return m, nil
		}
		hash, err := m.console.resolveUserHash(args[0])
		if err != nil {
			writef(&sb, styleRed, "%v\n", err)
			m.appendOutput(sb.String())
			return m, nil
		}
		files, err := m.console.srv.store.FilesByOwner(hash)
		if err != nil || len(files) == 0 {
			m.appendOutput(styleYellow.Render("No files found for that user.") + "\n")
			return m, nil
		}
		m.appendOutput(styleRedBold.Render(fmt.Sprintf(
			"This will permanently delete %d items owned by %s.",
			len(files), shortID(hash))) + "\n")
		m.confirmCmd = &pendingConfirm{
			prompt: "Type the user ID prefix to confirm, or anything else to cancel: ",
			onInput: func(answer string) string {
				if !strings.HasPrefix(hash, answer) || answer == "" {
					return styleYellow.Render("Cancelled.") + "\n"
				}
				deleted := 0
				for _, rel := range files {
					rel = strings.TrimSuffix(rel, "/")
					full := filepath.Join(m.console.srv.absUploadDir, filepath.FromSlash(rel))
					if os.RemoveAll(full) == nil {
						m.console.srv.store.DeletePath(rel)
						deleted++
					}
				}
				m.console.srv.store.LogEvent(EventAdmin, hash, m.console.sessionID, nil,
					"action", "purge", "count", deleted)
				return styleGreenBold.Render(fmt.Sprintf("Purged %d items.", deleted)) + "\n"
			},
		}
	}
	return m, nil
}

// ── runTUI ───────────────────────────────────────────────────────────────────

func (a *adminConsole) runTUI() {
	a.logger.Debug("Starting TUI")
	p := tea.NewProgram(
		initialAdminModel(a),
		tea.WithInput(a.ch),
		tea.WithOutput(a.ch),
		tea.WithAltScreen(),
	)
	if _, err := p.Run(); err != nil {
		a.logger.Error("admin TUI error", "err", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Panel: Log Viewer
// ─────────────────────────────────────────────────────────────────────────────

type logViewerModel struct {
	console *adminConsole
	vp      viewport.Model
	lines   []string
	width   int
	height  int
	ready   bool
	filter  string // current event-kind filter (empty = all)
	title   string
}

type logViewerDoneMsg struct{}

func (a *adminConsole) buildLogLines(n int, userFilter, eventFilter, ipFilter string) []string {
	var out strings.Builder
	a.cmdLogs([]string{strconv.Itoa(n)}, userFilter, eventFilter, ipFilter, &out)
	raw := strings.ReplaceAll(out.String(), "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	return lines
}

func (m logViewerModel) Init() tea.Cmd { return nil }

func (m logViewerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		vpH := m.height - 2 // header + footer
		if vpH < 1 {
			vpH = 1
		}
		if !m.ready {
			m.vp = viewport.New(m.width, vpH)
			m.vp.SetContent(strings.Join(m.lines, "\n"))
			m.vp.GotoBottom()
			m.ready = true
		} else {
			m.vp.Width = m.width
			m.vp.Height = vpH
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, tea.Quit
		case "g":
			m.vp.GotoTop()
			return m, nil
		case "G":
			m.vp.GotoBottom()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	return m, cmd
}

func (m logViewerModel) View() string {
	if !m.ready {
		return ""
	}
	w := m.width
	title := "LOG VIEWER — " + m.title
	hint := " q=back  ↑↓ PgUp/PgDn  g=top G=bottom "
	gap := w - lipgloss.Width(title) - lipgloss.Width(hint)
	if gap < 0 {
		gap = 0
	}
	header := stylePanelHeader.Copy().Width(w).Render(title + strings.Repeat(" ", gap) + hint)

	pct := "100%"
	if !m.vp.AtBottom() {
		pct = fmt.Sprintf("%d%%", int(m.vp.ScrollPercent()*100))
	}
	footerStr := fmt.Sprintf("  %d lines  ·  %s  ", len(m.lines), pct)
	footer := stylePanelFooter.Copy().Width(w).Render(footerStr)

	return header + "\n" + m.vp.View() + "\n" + footer
}

func (a *adminConsole) runLogViewer(args []string) {
	n := 200
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}
	lines := a.buildLogLines(n, "", "", "")
	title := fmt.Sprintf("last %d entries", n)

	m := logViewerModel{console: a, lines: lines, title: title}
	p := tea.NewProgram(m, tea.WithInput(a.ch), tea.WithOutput(a.ch), tea.WithAltScreen())
	p.Run() //nolint:errcheck
}

// ─────────────────────────────────────────────────────────────────────────────
// Panel: DB Viewer
// ─────────────────────────────────────────────────────────────────────────────

type dbRow = []string

type dbViewerModel struct {
	console   *adminConsole
	vp        viewport.Model
	tableName string
	cols      []string
	rows      []dbRow
	cursor    int
	width     int
	height    int
	ready     bool
	colWidths []int
}

func (a *adminConsole) loadDBTable(name string) (cols []string, rows []dbRow, err error) {
	var q string
	switch name {
	case "users":
		q = `SELECT pubkey_hash, last_login, upload_count, upload_bytes, download_count, download_bytes FROM users ORDER BY upload_bytes DESC`
		cols = []string{"hash", "last_login", "up_count", "up_bytes", "dn_count", "dn_bytes"}
	case "files":
		q = `SELECT path, owner_hash, size, is_dir FROM files ORDER BY size DESC LIMIT 500`
		cols = []string{"path", "owner", "size", "is_dir"}
	case "log":
		q = `SELECT timestamp, ip_address, port, user_id, event, path FROM log ORDER BY timestamp DESC LIMIT 500`
		cols = []string{"timestamp", "ip", "port", "user", "event", "path"}
	case "bans", "shadow_banned":
		q = `SELECT pubkey_hash, banned_at FROM shadow_banned ORDER BY banned_at DESC`
		cols = []string{"pubkey_hash", "banned_at"}
	case "ip_banned":
		q = `SELECT ip_address, banned_at FROM ip_banned ORDER BY banned_at DESC`
		cols = []string{"ip_address", "banned_at"}
	default:
		return nil, nil, fmt.Errorf("unknown table %q (use: users/files/log/bans/ip_banned)", name)
	}

	dbRows, err := a.srv.store.db.Query(q)
	if err != nil {
		return nil, nil, err
	}
	defer dbRows.Close()

	for dbRows.Next() {
		// Dynamic scanning into []any
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := dbRows.Scan(ptrs...); err != nil {
			continue
		}
		row := make(dbRow, len(cols))
		for i, v := range vals {
			switch val := v.(type) {
			case []byte:
				row[i] = string(val)
			case int64:
				// Pretty-print byte columns
				colName := cols[i]
				if strings.Contains(colName, "bytes") || colName == "size" {
					row[i] = formatBytes(val)
				} else if colName == "timestamp" {
					row[i] = time.Unix(val, 0).Format("2006-01-02 15:04:05")
				} else {
					row[i] = strconv.FormatInt(val, 10)
				}
			case string:
				row[i] = val
			case nil:
				row[i] = ""
			default:
				row[i] = fmt.Sprintf("%v", val)
			}
		}
		rows = append(rows, row)
	}
	return cols, rows, dbRows.Err()
}

func renderDBTable(cols []string, rows []dbRow, cursor, width int) ([]string, []int) {
	// Compute column widths
	colW := make([]int, len(cols))
	for i, c := range cols {
		colW[i] = len(c)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colW) && len(cell) > colW[i] {
				colW[i] = len(cell)
			}
		}
	}
	// Cap each column at a fraction of the terminal width
	maxCol := (width - len(cols)*3) / len(cols)
	if maxCol < 8 {
		maxCol = 8
	}
	for i := range colW {
		if colW[i] > maxCol {
			colW[i] = maxCol
		}
	}

	var lines []string

	// Header row
	var hdr strings.Builder
	hdr.WriteString("  ")
	for i, c := range cols {
		cell := fmt.Sprintf("%-*s", colW[i], c)
		if len(cell) > colW[i] {
			cell = cell[:colW[i]]
		}
		hdr.WriteString(styleCyanBold.Render(cell) + "  ")
	}
	lines = append(lines, hdr.String())
	lines = append(lines, styleDarkGray.Render(strings.Repeat("─", width-2)))

	for ri, row := range rows {
		var line strings.Builder
		line.WriteString("  ")
		for ci, cell := range row {
			if ci >= len(colW) {
				break
			}
			padded := cell
			if len(padded) > colW[ci] {
				padded = padded[:colW[ci]-1] + "…"
			}
			padded = fmt.Sprintf("%-*s", colW[ci], padded)
			if ri == cursor {
				line.WriteString(styleSelected.Render(padded) + "  ")
			} else {
				line.WriteString(styleWhite.Render(padded) + "  ")
			}
		}
		lines = append(lines, line.String())
	}
	return lines, colW
}

func (m dbViewerModel) Init() tea.Cmd { return nil }

func (m dbViewerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		vpH := m.height - 2
		if vpH < 1 {
			vpH = 1
		}
		lines, colW := renderDBTable(m.cols, m.rows, m.cursor, m.width)
		m.colWidths = colW
		if !m.ready {
			m.vp = viewport.New(m.width, vpH)
			m.vp.SetContent(strings.Join(lines, "\n"))
			m.ready = true
		} else {
			m.vp.Width = m.width
			m.vp.Height = vpH
			m.vp.SetContent(strings.Join(lines, "\n"))
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.refreshContent()
				// Scroll viewport to keep cursor visible
				lineIdx := m.cursor + 2 // 2 header lines
				if lineIdx < m.vp.YOffset {
					m.vp.SetYOffset(lineIdx)
				}
			}
			return m, nil

		case "down", "j":
			if m.cursor < len(m.rows)-1 {
				m.cursor++
				m.refreshContent()
				lineIdx := m.cursor + 2
				if lineIdx >= m.vp.YOffset+m.vp.Height {
					m.vp.SetYOffset(lineIdx - m.vp.Height + 1)
				}
			}
			return m, nil

		case "g":
			m.cursor = 0
			m.refreshContent()
			m.vp.GotoTop()
			return m, nil
		case "G":
			m.cursor = len(m.rows) - 1
			m.refreshContent()
			m.vp.GotoBottom()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	return m, cmd
}

func (m *dbViewerModel) refreshContent() {
	lines, _ := renderDBTable(m.cols, m.rows, m.cursor, m.width)
	m.vp.SetContent(strings.Join(lines, "\n"))
}

func (m dbViewerModel) View() string {
	if !m.ready {
		return ""
	}
	w := m.width
	title := fmt.Sprintf("DB VIEWER — %s  (%d rows)", m.tableName, len(m.rows))
	hint := " q=back  ↑↓=move  g=top G=bottom "
	gap := w - lipgloss.Width(title) - lipgloss.Width(hint)
	if gap < 0 {
		gap = 0
	}
	header := stylePanelHeader.Copy().Width(w).Render(title + strings.Repeat(" ", gap) + hint)

	rowInfo := ""
	if len(m.rows) > 0 {
		rowInfo = fmt.Sprintf("row %d/%d", m.cursor+1, len(m.rows))
	}
	footer := stylePanelFooter.Copy().Width(w).Render("  " + rowInfo)

	return header + "\n" + m.vp.View() + "\n" + footer
}

func (a *adminConsole) runDBViewer(args []string) {
	tableName := "users"
	if len(args) > 0 {
		tableName = strings.ToLower(args[0])
	}

	cols, rows, err := a.loadDBTable(tableName)
	if err != nil {
		// Write error to channel directly since we're not in a TUI yet
		fmt.Fprintf(a.ch, styleRed.Render(fmt.Sprintf("view-db: %v\r\n", err)))
		return
	}

	m := dbViewerModel{
		console:   a,
		tableName: tableName,
		cols:      cols,
		rows:      rows,
	}
	p := tea.NewProgram(m, tea.WithInput(a.ch), tea.WithOutput(a.ch), tea.WithAltScreen())
	p.Run() //nolint:errcheck
}

// ─────────────────────────────────────────────────────────────────────────────
// Panel: File Browser
// ─────────────────────────────────────────────────────────────────────────────

type fileEntry struct {
	name    string
	isDir   bool
	size    int64
	modTime time.Time
	owner   string
}

type fileBrowserModel struct {
	console *adminConsole
	dir     string // absolute path being browsed
	entries []fileEntry
	cursor  int
	width   int
	height  int
	ready   bool
	vp      viewport.Model
	preview string // non-empty = showing file preview pane
	status  string // one-line status message
}

func (a *adminConsole) readDir(absDir string) ([]fileEntry, error) {
	des, err := os.ReadDir(absDir)
	if err != nil {
		return nil, err
	}
	root := a.srv.absUploadDir
	var entries []fileEntry
	// Always add ".." unless we're at root
	if absDir != root {
		entries = append(entries, fileEntry{name: "..", isDir: true})
	}
	for _, de := range des {
		fi, err := de.Info()
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, filepath.Join(absDir, de.Name()))
		rel = filepath.ToSlash(rel)
		owner, _ := a.srv.store.GetFileOwner(rel)
		entries = append(entries, fileEntry{
			name:    de.Name(),
			isDir:   de.IsDir(),
			size:    fi.Size(),
			modTime: fi.ModTime(),
			owner:   owner,
		})
	}
	return entries, nil
}

func (m fileBrowserModel) buildListLines() []string {
	root := m.console.srv.absUploadDir
	rel, _ := filepath.Rel(root, m.dir)
	rel = filepath.ToSlash(rel)
	if rel == "." {
		rel = "/"
	} else {
		rel = "/" + rel
	}

	lines := []string{
		styleCyan.Render(rel) + "  " + styleDarkGray.Render(fmt.Sprintf("(%d entries)", len(m.entries))),
		styleDarkGray.Render(strings.Repeat("─", m.width-2)),
	}

	for i, e := range m.entries {
		modStr := e.modTime.Format("Jan 02 15:04")
		sizeStr := formatBytes(e.size)
		if e.isDir {
			sizeStr = "       "
		}
		ownerStr := shortID(e.owner)
		if ownerStr == "" {
			ownerStr = "?"
		}

		nameStr := e.name
		var styled string
		if e.isDir {
			styled = styleDir.Render(nameStr + "/")
		} else {
			if e.owner == systemOwner {
				styled = styleSysFile.Render(nameStr)
			} else {
				styled = styleFile.Render(nameStr)
			}
		}

		line := fmt.Sprintf("  %s  %7s  %-10s  %s",
			styleDarkGray.Render(modStr),
			styleLightGray.Render(sizeStr),
			styleDarkGray.Render(ownerStr),
			styled)

		if i == m.cursor {
			// Highlight the selected row (strip ANSI first for accurate width, then re-render)
			plain := fmt.Sprintf("  %s  %7s  %-10s  %s",
				modStr, sizeStr, ownerStr, nameStr)
			if e.isDir {
				plain = fmt.Sprintf("  %s  %7s  %-10s  %s/",
					modStr, sizeStr, ownerStr, nameStr)
			}
			_ = line // discard styled for selected
			line = styleSelected.Render(fmt.Sprintf("%-*s", m.width, plain))
		}
		lines = append(lines, line)
	}
	return lines
}

func (m fileBrowserModel) Init() tea.Cmd { return nil }

func (m fileBrowserModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		vpH := m.height - 3 // header + footer + status
		if vpH < 1 {
			vpH = 1
		}
		if !m.ready {
			m.vp = viewport.New(m.width, vpH)
			m.vp.SetContent(strings.Join(m.buildListLines(), "\n"))
			m.ready = true
		} else {
			m.vp.Width = m.width
			m.vp.Height = vpH
			m.refreshContent()
		}
		return m, nil

	case tea.KeyMsg:
		if m.preview != "" {
			// In preview mode, any key returns to list
			m.preview = ""
			m.refreshContent()
			return m, nil
		}

		switch msg.String() {
		case "q", "esc":
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.ensureVisible()
				m.refreshContent()
			}
			return m, nil

		case "down", "j":
			if m.cursor < len(m.entries)-1 {
				m.cursor++
				m.ensureVisible()
				m.refreshContent()
			}
			return m, nil

		case "g":
			m.cursor = 0
			m.vp.GotoTop()
			m.refreshContent()
			return m, nil
		case "G":
			m.cursor = len(m.entries) - 1
			m.vp.GotoBottom()
			m.refreshContent()
			return m, nil

		case "enter", "l", "right":
			if len(m.entries) == 0 {
				return m, nil
			}
			e := m.entries[m.cursor]
			if e.isDir {
				newDir := filepath.Join(m.dir, e.name)
				entries, err := m.console.readDir(newDir)
				if err != nil {
					m.status = styleRed.Render(fmt.Sprintf("error: %v", err))
					return m, nil
				}
				m.dir = newDir
				m.entries = entries
				m.cursor = 0
				m.vp.GotoTop()
				m.refreshContent()
			} else {
				// Open file for preview
				m.openPreview(e)
			}
			return m, nil

		case "backspace", "h", "left":
			root := m.console.srv.absUploadDir
			if m.dir == root {
				return m, nil
			}
			parent := filepath.Dir(m.dir)
			if !strings.HasPrefix(parent, root) {
				parent = root
			}
			// Find the cursor position for the directory we came from
			fromName := filepath.Base(m.dir)
			entries, err := m.console.readDir(parent)
			if err != nil {
				m.status = styleRed.Render(fmt.Sprintf("error: %v", err))
				return m, nil
			}
			m.dir = parent
			m.entries = entries
			m.cursor = 0
			for i, e := range entries {
				if e.name == fromName {
					m.cursor = i
					break
				}
			}
			m.ensureVisible()
			m.refreshContent()
			return m, nil

		case "p":
			if len(m.entries) > 0 {
				e := m.entries[m.cursor]
				if !e.isDir {
					m.openPreview(e)
				}
			}
			return m, nil

		case "d":
			// Quick delete with confirmation via status line
			if len(m.entries) > 0 {
				e := m.entries[m.cursor]
				if e.name == ".." {
					return m, nil
				}
				full := filepath.Join(m.dir, e.name)
				root := m.console.srv.absUploadDir
				rel, _ := filepath.Rel(root, full)
				rel = filepath.ToSlash(rel)
				if err := os.RemoveAll(full); err != nil {
					m.status = styleRed.Render(fmt.Sprintf("delete failed: %v", err))
				} else {
					m.console.srv.store.DeletePath(rel)
					m.console.srv.store.LogEvent(EventAdmin, "admin", m.console.sessionID, nil,
						"action", "rm", "path", rel)
					m.status = styleGreen.Render(fmt.Sprintf("deleted: %s", rel))
					// Reload directory
					entries, err := m.console.readDir(m.dir)
					if err == nil {
						m.entries = entries
						if m.cursor >= len(m.entries) {
							m.cursor = len(m.entries) - 1
						}
						if m.cursor < 0 {
							m.cursor = 0
						}
					}
					m.refreshContent()
				}
			}
			return m, nil

		case "b":
			// Quick ban: ban owner of selected file
			if len(m.entries) > 0 {
				e := m.entries[m.cursor]
				if !e.isDir && e.owner != "" && e.owner != systemOwner {
					if err := m.console.srv.store.Ban(e.owner); err != nil {
						m.status = styleRed.Render(fmt.Sprintf("ban failed: %v", err))
					} else {
						m.console.srv.store.LogEvent(EventShadowBan, e.owner, m.console.sessionID, nil,
							"action", "ban", "path", e.name)
						m.status = styleRedBold.Render(fmt.Sprintf("banned owner of: %s", e.name))
					}
				} else {
					m.status = styleYellow.Render("no bannable owner for this entry")
				}
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	return m, cmd
}

func (m *fileBrowserModel) ensureVisible() {
	lineIdx := m.cursor + 2 // 2 header lines in list
	if lineIdx < m.vp.YOffset {
		m.vp.SetYOffset(lineIdx)
	} else if lineIdx >= m.vp.YOffset+m.vp.Height {
		m.vp.SetYOffset(lineIdx - m.vp.Height + 1)
	}
}

func (m *fileBrowserModel) refreshContent() {
	if m.preview != "" {
		m.vp.SetContent(m.preview)
	} else {
		m.vp.SetContent(strings.Join(m.buildListLines(), "\n"))
	}
}

func (m *fileBrowserModel) openPreview(e fileEntry) {
	full := filepath.Join(m.dir, e.name)
	const maxPreview = 8192
	data, err := os.ReadFile(full)
	if err != nil {
		m.status = styleRed.Render(fmt.Sprintf("preview error: %v", err))
		return
	}
	if len(data) > maxPreview {
		data = append(data[:maxPreview], []byte("\n… (truncated)")...)
	}
	// Simple binary sniff
	isBinary := false
	for _, b := range data[:min(512, len(data))] {
		if b == 0 {
			isBinary = true
			break
		}
	}
	if isBinary {
		m.preview = styleYellow.Render(fmt.Sprintf("Binary file: %s (%s)", e.name, formatBytes(e.size)))
	} else {
		header := styleCyanBold.Render(fmt.Sprintf("── %s (%s) ──", e.name, formatBytes(e.size)))
		m.preview = header + "\n" + string(data)
	}
	m.status = styleDarkGray.Render("press any key to return to listing")
	m.vp.SetContent(m.preview)
	m.vp.GotoTop()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m fileBrowserModel) View() string {
	if !m.ready {
		return ""
	}
	w := m.width

	// Panel title
	root := m.console.srv.absUploadDir
	rel, _ := filepath.Rel(root, m.dir)
	rel = filepath.ToSlash(rel)
	if rel == "." {
		rel = "/"
	} else {
		rel = "/" + rel
	}

	title := "FILE BROWSER — " + rel
	hint := " q=back  ↑↓=move  Enter=open  p=preview  d=delete  b=ban  "
	gap := w - lipgloss.Width(title) - lipgloss.Width(hint)
	if gap < 0 {
		gap = 0
	}
	header := stylePanelHeader.Copy().Width(w).Render(title + strings.Repeat(" ", gap) + hint)

	statusLine := m.status
	if statusLine == "" {
		pct := "100%"
		if !m.vp.AtBottom() {
			pct = fmt.Sprintf("%d%%", int(m.vp.ScrollPercent()*100))
		}
		statusLine = styleDarkGray.Render(fmt.Sprintf("  %d entries  ·  %s  ", len(m.entries), pct))
	}
	footer := stylePanelFooter.Copy().Width(w).Render(statusLine)

	return header + "\n" + m.vp.View() + "\n" + footer
}

func (a *adminConsole) runFileBrowser(args []string) {
	startDir := a.srv.absUploadDir
	if len(args) > 0 {
		candidate := a.resolvePath(args[0])
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			startDir = candidate
		}
	}

	entries, err := a.readDir(startDir)
	if err != nil {
		fmt.Fprintf(a.ch, styleRed.Render(fmt.Sprintf("view-files: %v\r\n", err)))
		return
	}

	m := fileBrowserModel{
		console: a,
		dir:     startDir,
		entries: entries,
	}
	p := tea.NewProgram(m, tea.WithInput(a.ch), tea.WithOutput(a.ch), tea.WithAltScreen())
	p.Run() //nolint:errcheck
}

// ─────────────────────────────────────────────────────────────────────────────
// Fallback line-oriented REPL (no-PTY path)
// ─────────────────────────────────────────────────────────────────────────────

// runREPL is the original REPL, kept for clients that do not request a PTY.
// It still uses Lip Gloss for colour but writes directly with CRLF endings.
func (a *adminConsole) runREPL() {
	w := bufio.NewWriter(a.ch)
	r := bufio.NewReader(a.ch)

	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	write := func(s string) { fmt.Fprint(w, crlf(s)); w.Flush() }

	write("\r\n" + styleRedBold.Render("╔══════════════════════════════════════════╗") + "\r\n")
	write(styleRedBold.Render("║      sftpguy  ADMIN  CONSOLE             ║") + "\r\n")
	write(styleRedBold.Render("╚══════════════════════════════════════════╝") + "\r\n")
	write(styleDarkGray.Render("Server:  ") + styleWhiteBold.Render(a.srv.cfg.Name) +
		styleDarkGray.Render("   Port: ") + styleWhite.Render(fmt.Sprintf("%d", a.srv.cfg.Port)) + "\r\n")
	write(styleDarkGray.Render(fmt.Sprintf("Session: %s", a.sessionID[:16])) + "\r\n")
	write(styleDarkGray.Render(fmt.Sprintf("Time:    %s", time.Now().Format("2006-01-02 15:04:05 MST"))) + "\r\n")
	write(hrLine(72) + "\r\n")
	write(styleCyan.Render(`Type "help" for a list of commands, "exit" to disconnect.`) + "\r\n")

	for {
		prompt := styleRedBold.Render("admin") +
			styleDarkGray.Render("@") +
			styleYellow.Render(a.srv.cfg.Name) +
			" " + styleDarkGray.Render(a.cwdDisplay()) +
			" " + styleCyan.Render("» ")
		fmt.Fprint(w, prompt)
		w.Flush()

		line, err := r.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				a.logger.Warn("admin console read error", "err", err)
			}
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])
		args := parts[1:]

		a.logger.Info("admin command", "cmd", cmd, "args", args, "session", a.sessionID[:16])
		a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", "command", "cmd", cmd)

		// Destructive commands: inline confirmation over the raw channel.
		if cmd == "shutdown" || cmd == "purge" {
			output, exit := a.replConfirm(cmd, args, r, w)
			write(crlf(output))
			if exit {
				break
			}
			continue
		}

		output, exit := a.dispatch(cmd, args)
		write(crlf(output))
		if exit {
			break
		}
	}

	write("\r\n" + styleYellow.Render("Goodbye.") + "\r\n")
}

// replConfirm handles the inline confirmation prompts for the fallback REPL.
func (a *adminConsole) replConfirm(cmd string, args []string,
	r *bufio.Reader, w *bufio.Writer) (output string, exit bool) {

	var out strings.Builder
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

	switch cmd {
	case "shutdown":
		out.WriteString(styleRedBold.Render("WARNING: This will shut down the server for ALL users.\r\n"))
		out.WriteString(styleYellow.Render(`Type "SHUTDOWN" to confirm, or anything else to cancel: `))
		fmt.Fprint(w, crlf(out.String()))
		w.Flush()
		out.Reset()

		confirm, _ := r.ReadString('\n')
		confirm = strings.TrimRight(confirm, "\r\n")
		if confirm != "SHUTDOWN" {
			return styleYellow.Render("Cancelled.\n"), false
		}
		a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", "shutdown")
		go a.srv.Shutdown()
		return styleRedBold.Render("Shutting down…\n"), true

	case "purge":
		if len(args) == 0 {
			var sb strings.Builder
			writef(&sb, styleRed, "Usage: purge <hash>\n")
			return sb.String(), false
		}
		hash, err := a.resolveUserHash(args[0])
		if err != nil {
			var sb strings.Builder
			writef(&sb, styleRed, "%v\n", err)
			return sb.String(), false
		}
		files, ferr := a.srv.store.FilesByOwner(hash)
		if ferr != nil || len(files) == 0 {
			return styleYellow.Render("No files found for that user.\n"), false
		}

		prompt := styleRedBold.Render(fmt.Sprintf(
			"This will permanently delete %d items owned by %s.\r\n", len(files), shortID(hash)))
		prompt += styleYellow.Render("Type the user ID prefix to confirm, or anything else to cancel: ")
		fmt.Fprint(w, crlf(prompt))
		w.Flush()

		confirm, _ := r.ReadString('\n')
		confirm = strings.TrimRight(confirm, "\r\n")
		if !strings.HasPrefix(hash, confirm) || confirm == "" {
			return styleYellow.Render("Cancelled.\n"), false
		}
		deleted := 0
		for _, rel := range files {
			rel = strings.TrimSuffix(rel, "/")
			full := filepath.Join(a.srv.absUploadDir, filepath.FromSlash(rel))
			if os.RemoveAll(full) == nil {
				a.srv.store.DeletePath(rel)
				deleted++
			}
		}
		a.srv.store.LogEvent(EventAdmin, hash, a.sessionID, nil, "action", "purge", "count", deleted)
		return styleGreenBold.Render(fmt.Sprintf("Purged %d items.\n", deleted)), false
	}
	return "", false
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helper — writes a styled, formatted line into a strings.Builder
// ─────────────────────────────────────────────────────────────────────────────

// writef renders a styled, formatted string into sb.
// The format string should include its own trailing newline where appropriate.
func writef(sb *strings.Builder, style lipgloss.Style, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	// Render strips trailing whitespace/newlines; put them back.
	trail := ""
	trimmed := strings.TrimRight(msg, "\n")
	trail = strings.Repeat("\n", len(msg)-len(trimmed))
	sb.WriteString(style.Render(trimmed) + trail)
}

// hrLine returns a horizontal rule styled for the given column width.
func hrLine(width int) string {
	if width < 40 {
		width = 72
	}
	if width > 200 {
		width = 200
	}
	return styleDarkGray.Render(strings.Repeat("─", width))
}

func writeHR(sb *strings.Builder) {
	sb.WriteString(hrLine(72) + "\n")
}

func writeHRW(sb *strings.Builder, width int) {
	sb.WriteString(hrLine(width) + "\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Autocomplete
// ─────────────────────────────────────────────────────────────────────────────

// fileArgCommands is the set of commands whose first argument is a path inside
// the upload root. We offer filesystem completion for their arguments.
var fileArgCommands = map[string]bool{
	"cat": true, "rm": true, "mv": true, "chown": true,
	"protect": true, "unprotect": true, "unrestrict": true, "restrict": true,
	"inspect": true, "i": true, "ban": true, "ls": true, "cd": true,
	"view-files": true, "vf": true,
}

// complete returns the new completions slice and selected index given the
// current input value and the previous completion state.
func (a *adminConsole) complete(value string, prev []string, prevIdx int) ([]string, int) {
	if len(prev) > 1 {
		next := (prevIdx + 1) % len(prev)
		return prev, next
	}

	parts := strings.Fields(value)
	trailingSpace := len(value) > 0 && value[len(value)-1] == ' '

	// ── Command-name completion ──────────────────────────────────────────
	if len(parts) == 0 || (len(parts) == 1 && !trailingSpace) {
		prefix := ""
		if len(parts) == 1 {
			prefix = strings.ToLower(parts[0])
		}
		seen := map[string]bool{}
		var candidates []string
		for _, c := range a.registry {
			if seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			if strings.HasPrefix(c.Name, prefix) {
				candidates = append(candidates, c.Name)
			}
			for _, alias := range c.Aliases {
				if strings.HasPrefix(alias, prefix) {
					candidates = append(candidates, alias)
				}
			}
		}
		sort.Strings(candidates)
		if len(candidates) == 0 {
			return nil, -1
		}
		return candidates, 0
	}

	// ── Path completion ──────────────────────────────────────────────────
	cmd := strings.ToLower(parts[0])
	if !fileArgCommands[cmd] {
		return nil, -1
	}

	pathPrefix := ""
	if !trailingSpace && len(parts) > 1 {
		pathPrefix = parts[len(parts)-1]
	}

	var dirPart, filePart string
	if strings.Contains(pathPrefix, "/") {
		dirPart = pathPrefix[:strings.LastIndex(pathPrefix, "/")+1]
		filePart = pathPrefix[strings.LastIndex(pathPrefix, "/")+1:]
	} else {
		dirPart = ""
		filePart = pathPrefix
	}

	searchDir := a.resolvePath(dirPart)
	entries, err := os.ReadDir(searchDir)
	if err != nil {
		return nil, -1
	}

	var inputPrefix string
	if !trailingSpace && len(parts) > 1 {
		inputPrefix = strings.Join(parts[:len(parts)-1], " ") + " " + dirPart
	} else {
		inputPrefix = strings.Join(parts, " ") + " " + dirPart
	}

	var candidates []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, filePart) {
			continue
		}
		completion := inputPrefix + name
		if e.IsDir() {
			completion += "/"
		}
		candidates = append(candidates, completion)
	}

	if len(candidates) == 0 {
		return nil, -1
	}
	sort.Strings(candidates)
	return candidates, 0
}

func (a *adminConsole) cwdDisplay() string {
	if a.cwd == "" {
		return "/"
	}
	return "/" + filepath.ToSlash(a.cwd)
}

// ─────────────────────────────────────────────────────────────────────────────
// Host key helpers
// ─────────────────────────────────────────────────────────────────────────────

func (s *Server) adminHostKeyHash() string {
	keyBytes, err := os.ReadFile(s.cfg.HostKeyFile)
	if err != nil {
		return ""
	}
	priv, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return ""
	}
	return sshPubKeyHash(priv.PublicKey())
}

func sshPubKeyHash(pub ssh.PublicKey) string {
	return fmt.Sprintf("%x", sha256.Sum256(pub.Marshal()))
}

func (s *Server) isAdminConn(perms *ssh.Permissions) bool {
	if perms == nil {
		return false
	}
	return perms.Extensions["admin"] == "1"
}

func (s *Server) checkAdminKey(key ssh.PublicKey) bool {
	return sshPubKeyHash(key) == s.adminHostKeyHash()
}

func (s *Server) logAdminLogin(pubHash, sessionID string, remoteAddr net.Addr) {
	s.logger.Info("admin login", userGroup(pubHash, sessionID, remoteAddr))
	s.store.LogEvent(EventAdminLogin, pubHash, sessionID, remoteAddr)
}

func (s *Server) handleAdminChannel(ch ssh.Channel, reqs <-chan *ssh.Request, sessionID string) {
	defer ch.Close()
	console := newAdminConsole(s, ch, sessionID)
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			req.Reply(true, nil)
			console.hasPTY = true
		case "shell":
			req.Reply(true, nil)
			console.Run()
			return
		case "env":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ban / shadow-ban store methods
// ─────────────────────────────────────────────────────────────────────────────

func (s *Store) IsBanned(pubkeyHash string) bool {
	var exists bool
	s.db.QueryRow("SELECT 1 FROM shadow_banned WHERE pubkey_hash = ?", pubkeyHash).Scan(&exists) //nolint:errcheck
	return exists
}

func (s *Store) IsBannedByIp(remoteAddr net.Addr) bool {
	return s.IsIPBanned(remoteToIP(remoteAddr))
}

func (s *Store) Ban(pubkeyHash string) error {
	_, err := s.exec(`INSERT OR IGNORE INTO shadow_banned (pubkey_hash) VALUES (?)`, pubkeyHash)
	return err
}

func (s *Store) Unban(pubkeyHash string) error {
	_, err := s.exec(`DELETE FROM shadow_banned WHERE pubkey_hash = ?`, pubkeyHash)
	return err
}

func (s *Store) BanByPath(path string) error {
	owner, err := s.GetFileOwner(path)
	if err != nil {
		return err
	}
	if owner == "" || owner == systemOwner {
		return fmt.Errorf("path %q has no bannable owner", path)
	}
	return s.Ban(owner)
}

func (s *Store) BanIP(ip string) error {
	if _, err := s.exec(`INSERT OR IGNORE INTO ip_banned (ip_address) VALUES (?)`, ip); err != nil {
		return err
	}
	ipHash := ipToHash(ip)
	_, err := s.exec(`INSERT OR IGNORE INTO shadow_banned (pubkey_hash) VALUES (?)`, ipHash)
	return err
}

func (s *Store) UnbanIP(ip string) error {
	if _, err := s.exec(`DELETE FROM ip_banned WHERE ip_address = ?`, ip); err != nil {
		return err
	}
	ipHash := ipToHash(ip)
	_, err := s.exec(`DELETE FROM shadow_banned WHERE pubkey_hash = ?`, ipHash)
	return err
}

func (s *Store) IsIPBanned(ip string) bool {
	var exists bool
	s.db.QueryRow("SELECT 1 FROM ip_banned WHERE ip_address = ?", ip).Scan(&exists) //nolint:errcheck
	return exists
}

func (s *Store) ListIPBans() ([]string, error) {
	rows, err := s.db.Query("SELECT ip_address, banned_at FROM ip_banned ORDER BY banned_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip, at string
		if err := rows.Scan(&ip, &at); err != nil {
			continue
		}
		out = append(out, fmt.Sprintf("  %-24s  %s", ip, at))
	}
	return out, rows.Err()
}

func ipToHash(ip string) string {
	return fmt.Sprintf("ip:%x", sha256.Sum256([]byte(ip)))
}

func remoteToIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// ─────────────────────────────────────────────────────────────────────────────
// Path resolution
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) resolvePath(p string) string {
	root := a.srv.absUploadDir
	var full string
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		clean := filepath.Clean(strings.TrimPrefix(p, "/"))
		full = filepath.Join(root, clean)
	} else {
		full = filepath.Join(root, a.cwd, filepath.Clean(p))
	}
	if !strings.HasPrefix(filepath.Clean(full)+string(filepath.Separator),
		filepath.Clean(root)+string(filepath.Separator)) {
		return root
	}
	return full
}

func (a *adminConsole) toRel(full string) string {
	rel, err := filepath.Rel(a.srv.absUploadDir, full)
	if err != nil {
		return ""
	}
	return filepath.ToSlash(rel)
}

// ─────────────────────────────────────────────────────────────────────────────
// Command implementations — Files
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) cmdPwd(out *strings.Builder) {
	out.WriteString(styleWhite.Render(a.cwdDisplay()) + "\n")
}

func (a *adminConsole) cmdCd(args []string, out *strings.Builder) {
	target := ""
	if len(args) > 0 {
		target = args[0]
	}
	if target == "" || target == "/" {
		a.cwd = ""
		return
	}
	full := a.resolvePath(target)
	fi, err := os.Stat(full)
	if err != nil {
		writef(out, styleRed, "cd: %v\n", err)
		return
	}
	if !fi.IsDir() {
		writef(out, styleRed, "cd: %s: not a directory\n", target)
		return
	}
	rel, err := filepath.Rel(a.srv.absUploadDir, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		writef(out, styleRed, "cd: cannot leave upload root\n")
		return
	}
	if rel == "." {
		a.cwd = ""
	} else {
		a.cwd = filepath.ToSlash(rel)
	}
}

func (a *adminConsole) cmdLs(args []string, out *strings.Builder) {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	full := a.resolvePath(target)

	entries, err := os.ReadDir(full)
	if err != nil {
		writef(out, styleRed, "ls: %v\n", err)
		return
	}

	displayPath := "/" + filepath.ToSlash(strings.TrimPrefix(full, a.srv.absUploadDir))
	out.WriteString(styleCyan.Render(displayPath+":") + "\n")

	fileCount, dirCount := 0, 0
	for _, e := range entries {
		fi, _ := e.Info()
		if fi == nil {
			continue
		}
		sizeStr := fmt.Sprintf("%8s", formatBytes(fi.Size()))
		modStr := fi.ModTime().Format("2006-01-02 15:04")
		name := e.Name()
		if e.IsDir() {
			name = styleBlueBold.Render(name + "/")
			sizeStr = "        "
			dirCount++
		} else {
			name = styleWhite.Render(name)
			fileCount++
		}
		relPath := a.toRel(filepath.Join(full, e.Name()))
		owner, _ := a.srv.store.GetFileOwner(relPath)
		if owner == "" {
			owner = "?"
		}
		out.WriteString(fmt.Sprintf("  %s  %s  %-16s  %s\n",
			styleDarkGray.Render(modStr),
			styleLightGray.Render(sizeStr),
			styleDarkGray.Render(shortID(owner)),
			name))
	}
	out.WriteString(styleDarkGray.Render(fmt.Sprintf("  %d file(s), %d dir(s)\n", fileCount, dirCount)))
}

func (a *adminConsole) cmdCat(args []string, out *strings.Builder) {
	if len(args) == 0 {
		writef(out, styleRed, "Usage: cat <path>\n")
		return
	}
	full := a.resolvePath(args[0])
	data, err := os.ReadFile(full)
	if err != nil {
		writef(out, styleRed, "cat: %v\n", err)
		return
	}
	out.WriteString(string(data) + "\n")
}

func (a *adminConsole) cmdRm(args []string, out *strings.Builder) {
	if len(args) == 0 {
		writef(out, styleRed, "Usage: rm <path>\n")
		return
	}
	full := a.resolvePath(args[0])
	rel := a.toRel(full)

	if err := os.RemoveAll(full); err != nil {
		writef(out, styleRed, "rm: %v\n", err)
		return
	}
	a.srv.store.DeletePath(rel)
	writef(out, styleGreen, "Deleted: %s\n", rel)
	a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", "rm", "path", rel)
}

func (a *adminConsole) cmdMv(args []string, out *strings.Builder) {
	if len(args) < 2 {
		writef(out, styleRed, "Usage: mv <src> <dst>\n")
		return
	}
	srcFull := a.resolvePath(args[0])
	dstFull := a.resolvePath(args[1])
	srcRel := a.toRel(srcFull)
	dstRel := a.toRel(dstFull)

	if err := os.Rename(srcFull, dstFull); err != nil {
		writef(out, styleRed, "mv: %v\n", err)
		return
	}
	a.srv.store.RenamePath(srcRel, dstRel)
	writef(out, styleGreen, "Moved: %s → %s\n", srcRel, dstRel)
	a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil,
		"action", "mv", "src", srcRel, "dst", dstRel)
}

func (a *adminConsole) cmdChown(args []string, out *strings.Builder) {
	if len(args) < 2 {
		writef(out, styleRed, "Usage: chown <pubkey_hash_prefix> <path>\n")
		return
	}
	resolved, err := a.resolveUserHash(args[0])
	if err != nil {
		writef(out, styleRed, "chown: %v\n", err)
		return
	}
	rel := a.toRel(a.resolvePath(args[1]))
	_, err = a.srv.store.db.Exec(
		"UPDATE files SET owner_hash = ? WHERE path = ? OR substr(path,1,?) = ?",
		resolved, rel, len(rel)+1, rel+"/")
	if err != nil {
		writef(out, styleRed, "chown: DB error: %v\n", err)
		return
	}
	writef(out, styleGreen, "Ownership of %q transferred to %s\n", rel, shortID(resolved))
	a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil,
		"action", "chown", "path", rel, "new_owner", resolved)
}

func (a *adminConsole) cmdProtect(args []string, protect bool, out *strings.Builder) {
	verb := "protect"
	if !protect {
		verb = "unprotect"
	}
	if len(args) == 0 {
		writef(out, styleRed, "Usage: %s <path>\n", verb)
		return
	}
	rel := a.toRel(a.resolvePath(args[0]))
	var err error
	if protect {
		_, err = a.srv.store.db.Exec(
			"UPDATE files SET owner_hash = ? WHERE path = ?", systemOwner, rel)
	} else {
		_, err = a.srv.store.db.Exec(
			"UPDATE files SET owner_hash = NULL WHERE path = ? AND owner_hash = ?",
			rel, systemOwner)
	}
	if err != nil {
		writef(out, styleRed, "%s: DB error: %v\n", verb, err)
		return
	}
	writef(out, styleGreen, "Done: %s %q\n", verb, rel)
	a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", verb, "path", rel)
}

func (a *adminConsole) cmdUnrestrict(args []string, add bool, out *strings.Builder) {
	if len(args) == 0 {
		writef(out, styleRed, "Usage: unrestrict/restrict <path>\n")
		return
	}
	p := args[0]
	if add {
		a.srv.cfg.unrestrictedMap[p] = true
		writef(out, styleGreen, "Added %q to unrestricted paths (runtime only; restart to persist).\n", p)
	} else {
		delete(a.srv.cfg.unrestrictedMap, p)
		out.WriteString(styleYellow.Render(fmt.Sprintf("Removed %q from unrestricted paths (runtime only).\n", p)))
	}
	a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil,
		"action", "unrestrict", "path", p, "add", add)
}

func (a *adminConsole) cmdInspect(args []string, out *strings.Builder) {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	full := a.resolvePath(target)
	rel := a.toRel(full)

	fi, err := os.Stat(full)
	if err != nil {
		writef(out, styleRed, "inspect: %v\n", err)
		return
	}
	owner, _ := a.srv.store.GetFileOwner(rel)
	if owner == "" {
		owner = "(none)"
	}
	typeStr := "file"
	if fi.IsDir() {
		typeStr = "directory"
	}

	writeHR(out)
	inspectRow := func(label, value string) {
		out.WriteString(fmt.Sprintf("  %s  %s\n",
			styleCyan.Render(fmt.Sprintf("%-12s", label)),
			styleWhite.Render(value)))
	}
	inspectRow("Path:", "/"+rel)
	inspectRow("Type:", typeStr)
	inspectRow("Size:", formatBytes(fi.Size()))
	inspectRow("Modified:", fi.ModTime().Format("2006-01-02 15:04:05"))
	inspectRow("Owner:", shortID(owner))
	inspectRow("Permissions:", fi.Mode().String())
	inspectRow("Unrestricted:", fmt.Sprintf("%v", a.srv.cfg.unrestrictedMap[rel] || a.srv.cfg.unrestrictedMap[rel+"/"]))
	writeHR(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Command implementations — Users
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) cmdUsers(out *strings.Builder) {
	rows, err := a.srv.store.db.Query(`
		SELECT u.pubkey_hash, u.last_login, u.upload_count, u.upload_bytes,
		       u.download_count, u.download_bytes,
		       CASE WHEN s.pubkey_hash IS NOT NULL THEN 1 ELSE 0 END as banned
		FROM users u
		LEFT JOIN shadow_banned s ON s.pubkey_hash = u.pubkey_hash
		ORDER BY u.upload_bytes DESC`)
	if err != nil {
		writef(out, styleRed, "DB error: %v\n", err)
		return
	}
	defer rows.Close()

	writeHR(out)
	out.WriteString(fmt.Sprintf("  %-14s  %-20s  %-10s  %-12s  %-12s  %-6s\n",
		styleCyan.Render("ID (prefix)"), styleCyan.Render("Last login"),
		styleCyan.Render("Uploads"), styleCyan.Render("Up bytes"),
		styleCyan.Render("Dn bytes"), styleCyan.Render("Banned")))
	writeHR(out)

	count := 0
	for rows.Next() {
		var hash, lastLogin string
		var upCount, upBytes, dnCount, dnBytes int64
		var banned bool
		if err := rows.Scan(&hash, &lastLogin, &upCount, &upBytes, &dnCount, &dnBytes, &banned); err != nil {
			continue
		}
		if hash == "system" {
			continue
		}
		banStr := "      "
		if banned {
			banStr = styleRedBold.Render("BANNED")
		}
		out.WriteString(fmt.Sprintf("  %-14s  %-20s  %-10d  %-12s  %-12s  %s\n",
			shortID(hash), lastLogin, upCount,
			formatBytes(upBytes), formatBytes(dnBytes), banStr))
		count++
	}
	writeHR(out)
	out.WriteString(fmt.Sprintf("  %d users total\n", count))
}

func (a *adminConsole) cmdUser(args []string, out *strings.Builder) {
	if len(args) == 0 {
		writef(out, styleRed, "Usage: user <hash>\n")
		return
	}
	hash, err := a.resolveUserHash(args[0])
	if err != nil {
		writef(out, styleRed, "%v\n", err)
		return
	}

	stats, err := a.srv.store.GetUserStats(hash)
	if err != nil {
		writef(out, styleRed, "%v\n", err)
		return
	}

	isBanned := a.srv.store.IsBanned(hash)
	isContrib, needed := stats.IsContributor(a.srv.cfg.ContributorThreshold)
	files, _ := a.srv.store.FilesByOwner(hash)

	writeHR(out)
	out.WriteString(styleYellowBold.Render("User: "+hash) + "\n")
	userRow := func(label, value string) {
		out.WriteString(fmt.Sprintf("  %s  %s\n",
			styleCyan.Render(fmt.Sprintf("%-18s", label)),
			styleWhite.Render(value)))
	}
	userRow("Last login:", stats.LastLogin)
	userRow("Uploads:", fmt.Sprintf("%d files, %s", stats.UploadCount, formatBytes(stats.UploadBytes)))
	userRow("Downloads:", fmt.Sprintf("%d files, %s", stats.DownloadCount, formatBytes(stats.DownloadBytes)))

	contribStr := fmt.Sprintf("%v", isContrib)
	if !isContrib {
		contribStr += fmt.Sprintf(" (needs %s more)", formatBytes(needed))
	}
	userRow("Contributor:", contribStr)

	bannedStr := "no"
	if isBanned {
		bannedStr = styleRedBold.Render("YES — shadow-banned")
	}
	out.WriteString(fmt.Sprintf("  %s  %s\n",
		styleCyan.Render(fmt.Sprintf("%-18s", "Shadow-banned:")),
		bannedStr))
	userRow("Files owned:", fmt.Sprintf("%d", len(files)))
	if len(files) > 0 {
		maxShow := 20
		if len(files) < maxShow {
			maxShow = len(files)
		}
		for _, f := range files[:maxShow] {
			out.WriteString("    " + styleDarkGray.Render(f) + "\n")
		}
		if len(files) > maxShow {
			out.WriteString(fmt.Sprintf("    … and %d more\n", len(files)-maxShow))
		}
	}
	writeHR(out)
}

func (a *adminConsole) cmdBan(args []string, ban bool, out *strings.Builder) {
	verb := "ban"
	if !ban {
		verb = "unban"
	}
	if len(args) == 0 {
		writef(out, styleRed, "Usage: %s <hash|path>\n", verb)
		return
	}

	arg := args[0]

	isPath := strings.ContainsAny(arg, "/\\") || strings.HasPrefix(arg, ".")
	if !isPath {
		full := a.resolvePath(arg)
		if _, err := os.Stat(full); err == nil {
			if _, resolveErr := a.resolveUserHash(arg); resolveErr != nil {
				isPath = true
			}
		}
	}

	if isPath {
		if !ban {
			writef(out, styleRed, "unban by path is not supported; use 'unban <hash>' instead\n")
			return
		}
		full := a.resolvePath(arg)
		rel := a.toRel(full)
		owner, err := a.srv.store.GetFileOwner(rel)
		if err != nil || owner == "" {
			writef(out, styleRed, "ban: path %q not found in database\n", rel)
			return
		}
		if owner == systemOwner {
			writef(out, styleRed, "ban: %q is system-owned; cannot ban system\n", rel)
			return
		}
		if err := a.srv.store.Ban(owner); err != nil {
			writef(out, styleRed, "Ban error: %v\n", err)
			return
		}
		out.WriteString(styleRedBold.Render(fmt.Sprintf("Shadow-banned owner of %q: %s", rel, shortID(owner))) + "\n")
		a.srv.store.LogEvent(EventShadowBan, owner, a.sessionID, nil, "action", "ban", "path", rel)
		return
	}

	hash, err := a.resolveUserHash(arg)
	if err != nil {
		writef(out, styleRed, "%v\n", err)
		return
	}

	if ban {
		if err := a.srv.store.Ban(hash); err != nil {
			writef(out, styleRed, "Ban error: %v\n", err)
			return
		}
		writeHR(out)
		out.WriteString(styleRedBold.Render(fmt.Sprintf("  ✗  Shadow-banned: %s", shortID(hash))) + "\n")
		writeHR(out)
		a.srv.store.LogEvent(EventShadowBan, hash, a.sessionID, nil, "action", "ban")
	} else {
		if err := a.srv.store.Unban(hash); err != nil {
			writef(out, styleRed, "Unban error: %v\n", err)
			return
		}
		writeHR(out)
		out.WriteString(styleGreenBold.Render(fmt.Sprintf("  ✓  Unbanned: %s", shortID(hash))) + "\n")
		writeHR(out)
		a.srv.store.LogEvent(EventAdmin, hash, a.sessionID, nil, "action", "unban")
	}
}

// cmdPurge is handled via startConfirm in the TUI path and replConfirm in the
// REPL path; this stub is here so dispatch() can find it when called directly.
func (a *adminConsole) cmdPurge(args []string, out *strings.Builder) bool {
	writef(out, styleRed, "purge: internal error — should be handled by confirmation flow\n")
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Command implementations — IP / Network
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) cmdIPBan(args []string, ban bool, out *strings.Builder) {
	verb := "ip-ban"
	if !ban {
		verb = "ip-unban"
	}
	if len(args) == 0 {
		writef(out, styleRed, "Usage: %s <ip>\n", verb)
		return
	}
	ip := args[0]
	if net.ParseIP(ip) == nil {
		writef(out, styleRed, "ip-ban: %q does not look like a valid IP address\n", ip)
		return
	}
	if ban {
		if err := a.srv.store.BanIP(ip); err != nil {
			writef(out, styleRed, "Error: %v\n", err)
			return
		}
		writeHR(out)
		out.WriteString(styleRedBold.Render(fmt.Sprintf("  ✗  IP shadow-banned: %s", ip)) + "\n")
		writeHR(out)
		a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", "ip-ban", "ip", ip)
	} else {
		if err := a.srv.store.UnbanIP(ip); err != nil {
			writef(out, styleRed, "Error: %v\n", err)
			return
		}
		writeHR(out)
		out.WriteString(styleGreenBold.Render(fmt.Sprintf("  ✓  IP unbanned: %s", ip)) + "\n")
		writeHR(out)
		a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", "ip-unban", "ip", ip)
	}
}

func (a *adminConsole) cmdIPList(out *strings.Builder) {
	bans, err := a.srv.store.ListIPBans()
	if err != nil {
		writef(out, styleRed, "DB error: %v\n", err)
		return
	}
	if len(bans) == 0 {
		out.WriteString(styleYellow.Render("No IP bans.") + "\n")
		return
	}
	writeHR(out)
	out.WriteString(fmt.Sprintf("  %s  %s\n",
		styleCyan.Render(fmt.Sprintf("%-24s", "IP address")),
		styleCyan.Render("Banned at")))
	writeHR(out)
	for _, b := range bans {
		out.WriteString(styleLightGray.Render(b) + "\n")
	}
	writeHR(out)
	out.WriteString(fmt.Sprintf("  %d banned IPs\n", len(bans)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Command implementations — Logs
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) cmdLogs(args []string, userFilter, eventFilter, ipFilter string, out *strings.Builder) {
	n := 50
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}

	q := `SELECT timestamp, ip_address, port, user_id, event, path, meta
	      FROM log WHERE 1=1`
	var qargs []any

	if userFilter != "" {
		resolved, err := a.resolveUserHash(userFilter)
		if err == nil {
			q += " AND user_id = ?"
			qargs = append(qargs, resolved)
		} else {
			q += " AND user_id LIKE ?"
			qargs = append(qargs, userFilter+"%")
		}
	}
	if eventFilter != "" {
		q += " AND event = ?"
		qargs = append(qargs, eventFilter)
	}
	if ipFilter != "" {
		q += " AND ip_address = ?"
		qargs = append(qargs, ipFilter)
	}
	q += " ORDER BY timestamp DESC LIMIT ?"
	qargs = append(qargs, n)

	rows, err := a.srv.store.db.Query(q, qargs...)
	if err != nil {
		writef(out, styleRed, "DB error: %v\n", err)
		return
	}
	defer rows.Close()

	type logRow struct {
		ts, ip, userID, event, path, meta string
		port                              int
	}
	var entries []logRow
	for rows.Next() {
		var ts int64
		var ip, userID, event string
		var port int
		var path, meta sql.NullString
		if err := rows.Scan(&ts, &ip, &port, &userID, &event, &path, &meta); err != nil {
			continue
		}
		entries = append(entries, logRow{
			ts:     time.Unix(ts, 0).Format("2006-01-02 15:04:05"),
			ip:     fmt.Sprintf("%s:%d", ip, port),
			userID: shortID(userID),
			event:  event,
			path:   path.String,
			meta:   meta.String,
		})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].ts < entries[j].ts })

	writeHR(out)
	out.WriteString(fmt.Sprintf("  %s  %-18s  %-16s  %-28s  %s\n",
		styleCyan.Render("Timestamp"),
		styleCyan.Render("IP"),
		styleCyan.Render("User"),
		styleCyan.Render("Event"),
		styleCyan.Render("Detail")))
	writeHR(out)
	for _, e := range entries {
		eventPadded := fmt.Sprintf("%-28s", e.event)
		var eventCol string
		switch {
		case strings.HasPrefix(e.event, "upload"):
			eventCol = styleGreen.Render(eventPadded)
		case strings.HasPrefix(e.event, "download"):
			eventCol = styleBlue.Render(eventPadded)
		case strings.HasPrefix(e.event, "admin"):
			eventCol = styleYellow.Render(eventPadded)
		case strings.HasPrefix(e.event, "ban"), strings.HasPrefix(e.event, "shadow"):
			eventCol = styleRed.Render(eventPadded)
		case strings.HasPrefix(e.event, "login"):
			eventCol = styleCyan.Render(eventPadded)
		default:
			eventCol = styleLightGray.Render(eventPadded)
		}

		extra := e.path
		if extra == "" {
			extra = e.meta
		}
		if len(extra) > 60 {
			extra = extra[:60] + "…"
		}
		out.WriteString(fmt.Sprintf("  %s  %-18s  %-16s  %s  %s\n",
			styleDarkGray.Render(e.ts),
			styleLightGray.Render(e.ip),
			styleDarkGray.Render(e.userID),
			eventCol,
			styleWhite.Render(extra)))
	}
	writeHR(out)
	out.WriteString(fmt.Sprintf("  Showing %d entries\n", len(entries)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Command implementations — Stats
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) cmdStats(out *strings.Builder) {
	u, c, f, b := a.srv.store.GetBannerStats(a.srv.cfg.ContributorThreshold)

	var dirCount, bannedCount, logCount int
	a.srv.store.db.QueryRow("SELECT COUNT(*) FROM files WHERE is_dir = 1").Scan(&dirCount) //nolint:errcheck
	a.srv.store.db.QueryRow("SELECT COUNT(*) FROM shadow_banned").Scan(&bannedCount)       //nolint:errcheck
	a.srv.store.db.QueryRow("SELECT COUNT(*) FROM log").Scan(&logCount)                    //nolint:errcheck

	writeHR(out)
	out.WriteString(styleYellowBold.Render("Server statistics:") + "\n")
	for _, row := range [][2]string{
		{"Users (ever logged in):", fmt.Sprintf("%d", u)},
		{"Contributors:", fmt.Sprintf("%d", c)},
		{"Shadow-banned users:", fmt.Sprintf("%d", bannedCount)},
		{"Files:", fmt.Sprintf("%d", f)},
		{"Directories:", fmt.Sprintf("%d", dirCount)},
		{"Total stored bytes:", formatBytes(int64(b))},
		{"Log entries:", fmt.Sprintf("%d", logCount)},
	} {
		out.WriteString(fmt.Sprintf("  %s  %s\n",
			styleDarkGray.Render(fmt.Sprintf("%-30s", row[0])),
			styleWhiteBold.Render(row[1])))
	}
	writeHR(out)
}

func (a *adminConsole) cmdTopUsers(args []string, mode string, out *strings.Builder) {
	n := 10
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}

	col, label := "upload_bytes", "Upload bytes"
	if mode == "download" {
		col, label = "download_bytes", "Download bytes"
	}

	q := fmt.Sprintf(`SELECT pubkey_hash, upload_bytes, download_bytes, upload_count, download_count
	                   FROM users WHERE %s > 0 ORDER BY %s DESC LIMIT ?`, col, col)
	rows, err := a.srv.store.db.Query(q, n)
	if err != nil {
		writef(out, styleRed, "DB error: %v\n", err)
		return
	}
	defer rows.Close()

	writeHR(out)
	out.WriteString(fmt.Sprintf("  %-4s  %-14s  %-14s  %s\n",
		styleCyan.Render("Rank"),
		styleCyan.Render("ID (prefix)"),
		styleCyan.Render(label),
		styleCyan.Render("Files")))
	writeHR(out)
	rank := 1
	for rows.Next() {
		var hash string
		var upBytes, dnBytes, upCount, dnCount int64
		if err := rows.Scan(&hash, &upBytes, &dnBytes, &upCount, &dnCount); err != nil {
			continue
		}
		byt, count := upBytes, upCount
		if mode == "download" {
			byt, count = dnBytes, dnCount
		}
		out.WriteString(fmt.Sprintf("  %4d. %-14s  %-14s  %d\n", rank, shortID(hash), formatBytes(byt), count))
		rank++
	}
	writeHR(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Command implementations — Server management
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) cmdConfig(out *strings.Builder) {
	cfg := a.srv.cfg
	writeHR(out)
	out.WriteString(styleYellowBold.Render("Running configuration:") + "\n")
	for _, r := range [][2]string{
		{"Name", cfg.Name},
		{"Port", fmt.Sprintf("%d", cfg.Port)},
		{"Host key", cfg.HostKeyFile},
		{"DB path", cfg.DBPath},
		{"Log file", cfg.LogFile},
		{"Upload dir", cfg.UploadDir},
		{"Banner file", cfg.BannerFile},
		{"Banner stats", fmt.Sprintf("%v", cfg.BannerStats)},
		{"Max file size", formatBytes(cfg.MaxFileSize)},
		{"Contributor threshold", formatBytes(cfg.ContributorThreshold)},
		{"Max dirs", fmt.Sprintf("%d", cfg.MaxDirs)},
		{"Mkdir rate", fmt.Sprintf("%.0f/s", cfg.MkdirRate)},
		{"Lock dirs to owners", fmt.Sprintf("%v", cfg.LockDirectoriesToOwners)},
		{"Unrestricted paths", fmt.Sprintf("%v", cfg.Unrestricted)},
	} {
		out.WriteString(fmt.Sprintf("  %s  %s\n",
			styleCyan.Render(fmt.Sprintf("%-28s", r[0])),
			styleWhite.Render(r[1])))
	}
	writeHR(out)
}

func (a *adminConsole) cmdReloadBanner(out *strings.Builder) {
	if _, err := os.Stat(a.srv.cfg.BannerFile); err != nil {
		writef(out, styleRed, "Banner file not found: %s\n", a.srv.cfg.BannerFile)
		return
	}
	writef(out, styleGreen, "Banner file %q is readable. It will be used on next connection.\n",
		a.srv.cfg.BannerFile)
	a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", "reload-banner")
}

// cmdShutdown is called from dispatch for the REPL path; TUI uses startConfirm.
func (a *adminConsole) cmdShutdown(out *strings.Builder) bool {
	out.WriteString(styleRedBold.Render("Use the interactive TUI or plain SSH to run shutdown.") + "\n")
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Command implementations — Help
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) cmdHelp(args []string, out *strings.Builder) {
	if len(args) > 0 {
		c, ok := a.byName[strings.ToLower(args[0])]
		if !ok {
			writef(out, styleRed, "No such command: %q\n", args[0])
			return
		}
		writeHR(out)
		out.WriteString("  " + styleYellowBold.Render(c.Usage) + "\n")
		out.WriteString("  " + styleDarkGray.Render(c.Help) + "\n")
		if len(c.Aliases) > 0 {
			out.WriteString("  Aliases: " + strings.Join(c.Aliases, ", ") + "\n")
		}
		writeHR(out)
		return
	}

	seen := make(map[string]bool)
	var categoryOrder []string
	byCategory := make(map[string][]AdminCommand)
	for _, c := range a.registry {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		if _, ok := byCategory[c.Category]; !ok {
			categoryOrder = append(categoryOrder, c.Category)
		}
		byCategory[c.Category] = append(byCategory[c.Category], c)
	}

	writeHR(out)
	for _, cat := range categoryOrder {
		out.WriteString("\n" + styleYellowBold.Render(cat) + "\n")
		for _, c := range byCategory[cat] {
			usagePadded := fmt.Sprintf("%-36s", c.Usage)
			out.WriteString(fmt.Sprintf("  %s %s\n",
				styleCyan.Render(usagePadded), styleDarkGray.Render(c.Help)))
		}
	}
	writeHR(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func (a *adminConsole) resolveUserHash(prefix string) (string, error) {
	if prefix == systemOwner {
		return systemOwner, nil
	}
	rows, err := a.srv.store.db.Query(
		"SELECT pubkey_hash FROM users WHERE pubkey_hash LIKE ?", prefix+"%")
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var matches []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			continue
		}
		matches = append(matches, h)
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no user matching %q", prefix)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous prefix %q: %d users match", prefix, len(matches))
	}
}
