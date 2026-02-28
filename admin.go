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

	"github.com/charmbracelet/bubbles/textinput"
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

	styleHR = styleDarkGray.Render(strings.Repeat("─", 72))

	styleBanner = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("1")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("1")).
			Padding(0, 2)
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
	a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", "login")

	if a.hasPTY {
		//a.logger.debug
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
	console   *adminConsole
	input     textinput.Model
	history   []string // command history
	histIdx   int      // current position in history (-1 = new entry)
	outputBuf string   // accumulated output rendered above the prompt
	quitting  bool

	// confirmCmd holds a pending destructive command waiting for user input.
	confirmCmd *pendingConfirm
}

// pendingConfirm represents a two-step confirmation prompt (purge, shutdown).
type pendingConfirm struct {
	prompt  string
	onInput func(answer string) string // returns output to display
}

type cmdResultMsg struct {
	output string
	exit   bool
}

func initialAdminModel(a *adminConsole) adminModel {
	ti := textinput.New()
	ti.Placeholder = "command…"
	ti.Focus()
	ti.CharLimit = 1024
	ti.Width = 72

	banner := styleBanner.Render("  sftpguy  ADMIN  CONSOLE  ") + "\n"
	meta := styleDarkGray.Render(fmt.Sprintf("Session: %s   Time: %s",
		a.sessionID[:16], time.Now().Format("2006-01-02 15:04:05"))) + "\n"
	hint := styleCyan.Render(`Type "help" for a list of commands.`) + "\n"

	return adminModel{
		console:   a,
		input:     ti,
		histIdx:   -1,
		outputBuf: banner + meta + hint,
	}
}

func (m adminModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m adminModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		if m.confirmCmd != nil {
			return m.handleConfirm(msg)
		}
		switch msg.Type {
		case tea.KeyEnter:
			raw := strings.TrimSpace(m.input.Value())
			m.input.SetValue("")
			m.histIdx = -1
			if raw == "" {
				return m, nil
			}
			// Push to history.
			m.history = append(m.history, raw)

			parts := strings.Fields(raw)
			cmd := strings.ToLower(parts[0])
			args := parts[1:]

			m.console.logger.Info("admin command", "cmd", cmd, "args", args,
				"session", m.console.sessionID[:16])
			m.console.srv.store.LogEvent(EventAdmin, "admin", m.console.sessionID, nil,
				"action", "command", "cmd", cmd)

			// Commands that need interactive confirmation get special handling.
			if cmd == "purge" || cmd == "shutdown" {
				return m.startConfirm(cmd, args)
			}

			output, exit := m.console.dispatch(cmd, args)
			m.outputBuf += output
			if exit {
				m.quitting = true
				return m, tea.Quit
			}
			return m, nil

		case tea.KeyUp:
			if len(m.history) == 0 {
				return m, nil
			}
			if m.histIdx == -1 {
				m.histIdx = len(m.history) - 1
			} else if m.histIdx > 0 {
				m.histIdx--
			}
			m.input.SetValue(m.history[m.histIdx])
			m.input.CursorEnd()
			return m, nil

		case tea.KeyDown:
			if m.histIdx == -1 {
				return m, nil
			}
			m.histIdx++
			if m.histIdx >= len(m.history) {
				m.histIdx = -1
				m.input.SetValue("")
			} else {
				m.input.SetValue(m.history[m.histIdx])
				m.input.CursorEnd()
			}
			return m, nil

		case tea.KeyCtrlC, tea.KeyEsc:
			m.quitting = true
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.input.Width = msg.Width - 20
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m adminModel) View() string {
	if m.quitting {
		return styleYellow.Render("Goodbye.") + "\n"
	}

	prompt := styleRedBold.Render("admin") +
		styleDarkGray.Render("@") +
		styleYellow.Render(m.console.srv.cfg.Name) +
		" " + styleDarkGray.Render(m.console.cwdDisplay()) +
		" " + styleCyanBold.Render("» ")

	if m.confirmCmd != nil {
		return m.outputBuf +
			styleYellowBold.Render(m.confirmCmd.prompt) + "\n" +
			prompt + m.input.View()
	}

	return m.outputBuf + "\n" + prompt + m.input.View()
}

// handleConfirm processes a keypress when we are waiting for confirmation.
func (m adminModel) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type != tea.KeyEnter {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	answer := strings.TrimSpace(m.input.Value())
	m.input.SetValue("")

	output := m.confirmCmd.onInput(answer)
	m.outputBuf += output
	m.confirmCmd = nil

	if strings.Contains(output, "Shutting down") {
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

// startConfirm sets up a two-step confirmation for dangerous commands.
func (m adminModel) startConfirm(cmd string, args []string) (adminModel, tea.Cmd) {
	switch cmd {
	case "shutdown":
		m.outputBuf += styleRedBold.Render("WARNING: This will shut down the server for ALL users.") + "\n"
		m.confirmCmd = &pendingConfirm{
			prompt: `Type "SHUTDOWN" to confirm, or anything else to cancel:`,
			onInput: func(answer string) string {
				if answer != "SHUTDOWN" {
					return styleYellow.Render("Cancelled.") + "\n"
				}
				out := styleRedBold.Render("Shutting down…") + "\n"
				m.console.srv.store.LogEvent(EventAdmin, "admin", m.console.sessionID, nil, "action", "shutdown")
				go m.console.srv.Shutdown()
				return out
			},
		}

	case "purge":
		var sb strings.Builder
		if len(args) == 0 {
			writef(&sb, styleRed, "Usage: purge <hash>\n")
			m.outputBuf += sb.String()
			return m, nil
		}
		hash, err := m.console.resolveUserHash(args[0])
		if err != nil {
			writef(&sb, styleRed, "%v\n", err)
			m.outputBuf += sb.String()
			return m, nil
		}
		files, err := m.console.srv.store.FilesByOwner(hash)
		if err != nil || len(files) == 0 {
			m.outputBuf += styleYellow.Render("No files found for that user.") + "\n"
			return m, nil
		}
		m.outputBuf += styleRedBold.Render(fmt.Sprintf(
			"This will permanently delete %d items owned by %s.",
			len(files), shortID(hash))) + "\n"
		m.confirmCmd = &pendingConfirm{
			prompt: "Type the user ID prefix to confirm, or anything else to cancel:",
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

// runTUI starts the Bubble Tea program over the SSH channel.
func (a *adminConsole) runTUI() {
	a.logger.Debug("Starting TUI")
	p := tea.NewProgram(
		initialAdminModel(a),
		tea.WithInput(a.ch),
		tea.WithOutput(a.ch),
	)
	if _, err := p.Run(); err != nil {
		a.logger.Error("admin TUI error", "err", err)
	}
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
	write(styleYellow.Render("Logged in as: ") + styleWhiteBold.Render("ADMIN") + "\r\n")
	write(styleDarkGray.Render(fmt.Sprintf("Session: %s   Time: %s\r\n",
		a.sessionID[:16], time.Now().Format("2006-01-02 15:04:05"))))
	write("\r\n" + styleCyan.Render(`Type "help" for a list of commands.`) + "\r\n")

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

func writef(sb *strings.Builder, style lipgloss.Style, format string, args ...any) {
	sb.WriteString(style.Render(fmt.Sprintf(format, args...)) + "\n")
}

func writeHR(sb *strings.Builder) {
	sb.WriteString(styleHR + "\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// cwdDisplay
// ─────────────────────────────────────────────────────────────────────────────

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
		out = append(out, fmt.Sprintf("%-20s  banned at %s", ip, at))
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
		} else {
			name = styleWhite.Render(name)
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
	out.WriteString(fmt.Sprintf("  %-18s %s\n", styleCyan.Render("Path:"), styleWhite.Render("/"+rel)))
	out.WriteString(fmt.Sprintf("  %-18s %s\n", styleCyan.Render("Type:"), typeStr))
	out.WriteString(fmt.Sprintf("  %-18s %s\n", styleCyan.Render("Size:"), formatBytes(fi.Size())))
	out.WriteString(fmt.Sprintf("  %-18s %s\n", styleCyan.Render("Modified:"), fi.ModTime().Format("2006-01-02 15:04:05")))
	out.WriteString(fmt.Sprintf("  %-18s %s\n", styleCyan.Render("Owner:"), shortID(owner)))
	out.WriteString(fmt.Sprintf("  %-18s %s\n", styleCyan.Render("Permissions:"), fi.Mode().String()))
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
	out.WriteString(fmt.Sprintf("  %-14s  %-20s  %-10s  %-10s  %-10s  %-6s\n",
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
		banStr := ""
		if banned {
			banStr = styleRedBold.Render("YES")
		}
		out.WriteString(fmt.Sprintf("  %-14s  %-20s  %-10d  %-10s  %-10s  %s\n",
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
	out.WriteString(styleYellowBold.Render(fmt.Sprintf("User: %s", hash)) + "\n")
	out.WriteString(fmt.Sprintf("  Last login:    %s\n", stats.LastLogin))
	out.WriteString(fmt.Sprintf("  Uploads:       %d files, %s\n", stats.UploadCount, formatBytes(stats.UploadBytes)))
	out.WriteString(fmt.Sprintf("  Downloads:     %d files, %s\n", stats.DownloadCount, formatBytes(stats.DownloadBytes)))
	contribStr := fmt.Sprintf("%v", isContrib)
	if !isContrib {
		contribStr += fmt.Sprintf(" (needs %s more)", formatBytes(needed))
	}
	out.WriteString(fmt.Sprintf("  Contributor:   %s\n", contribStr))
	out.WriteString(fmt.Sprintf("  Shadow-banned: %v\n", isBanned))
	out.WriteString(fmt.Sprintf("  Files owned:   %d\n", len(files)))
	if len(files) > 0 {
		max := 20
		if len(files) < max {
			max = len(files)
		}
		for _, f := range files[:max] {
			out.WriteString("    " + styleDarkGray.Render(f) + "\n")
		}
		if len(files) > max {
			out.WriteString(fmt.Sprintf("    … and %d more\n", len(files)-max))
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
		out.WriteString(styleRedBold.Render(fmt.Sprintf("Shadow-banned: %s", shortID(hash))) + "\n")
		a.srv.store.LogEvent(EventShadowBan, hash, a.sessionID, nil, "action", "ban")
	} else {
		if err := a.srv.store.Unban(hash); err != nil {
			writef(out, styleRed, "Unban error: %v\n", err)
			return
		}
		writef(out, styleGreen, "Unbanned: %s\n", shortID(hash))
		a.srv.store.LogEvent(EventAdmin, hash, a.sessionID, nil, "action", "unban")
	}
}

// cmdPurge is handled via startConfirm in the TUI path and replConfirm in the
// REPL path; this stub is here so dispatch() can find it when called directly.
func (a *adminConsole) cmdPurge(args []string, out *strings.Builder) bool {
	// Should not be reached via normal dispatch — confirmation flow handles it.
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
		out.WriteString(styleRedBold.Render(fmt.Sprintf("IP shadow-banned: %s", ip)) + "\n")
		a.srv.store.LogEvent(EventAdmin, "admin", a.sessionID, nil, "action", "ip-ban", "ip", ip)
	} else {
		if err := a.srv.store.UnbanIP(ip); err != nil {
			writef(out, styleRed, "Error: %v\n", err)
			return
		}
		writef(out, styleGreen, "IP unbanned: %s\n", ip)
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
	for _, b := range bans {
		out.WriteString(" " + b + "\n")
	}
	writeHR(out)
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
	for _, e := range entries {
		eventCol := styleCyan.Render(fmt.Sprintf("%-28s", e.event))
		extra := e.path
		if extra == "" {
			extra = e.meta
		}
		if len(extra) > 60 {
			extra = extra[:60] + "…"
		}
		out.WriteString(fmt.Sprintf("  %s  %-16s  %-14s  %s  %s\n",
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
		out.WriteString(fmt.Sprintf("  %-30s %s\n", row[0], styleWhiteBold.Render(row[1])))
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
	out.WriteString(fmt.Sprintf("  %-14s  %-14s  %-14s\n",
		styleCyan.Render("ID (prefix)"), styleCyan.Render(label), styleCyan.Render("Files")))
	writeHR(out)
	rank := 1
	for rows.Next() {
		var hash string
		var upBytes, dnBytes, upCount, dnCount int64
		if err := rows.Scan(&hash, &upBytes, &dnBytes, &upCount, &dnCount); err != nil {
			continue
		}
		bytes, count := upBytes, upCount
		if mode == "download" {
			bytes, count = dnBytes, dnCount
		}
		out.WriteString(fmt.Sprintf("  %2d. %-14s  %-14s  %d\n", rank, shortID(hash), formatBytes(bytes), count))
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
		out.WriteString(fmt.Sprintf("  %-28s %s\n", styleCyan.Render(r[0]), styleWhite.Render(r[1])))
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
	// In TUI mode this is handled by startConfirm. If somehow called directly,
	// refuse without confirmation.
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
			out.WriteString(fmt.Sprintf("  %-36s %s\n",
				styleCyan.Render(c.Usage), styleDarkGray.Render(c.Help)))
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
