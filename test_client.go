//go:build testclient

// sftpguy_test_client.go
//
// Usage:  go run -tags testclient test_client.go [flags]
//
// Flags:
//   -host       Server host (default: localhost)
//   -port       Server port (default: 2222)
//   -hostkey    Server public key .pub file (optional)
//   -system     A system-owned file on the server (default: README.txt)
//   -threshold  Contributor threshold bytes, match -contrib (default: 1048576)
//   -noauth     Run noClientAuth suite, server needs -noauth (default: true)
//   -explorer   Explorer base URL to run explorer HTTP suite (optional)
//   -v          Verbose error detail for all steps

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	flagHost      = flag.String("host", "localhost", "Server hostname")
	flagPort      = flag.Int("port", 2222, "Server port")
	flagHostKey   = flag.String("hostkey", "", "Path to server public key file (optional)")
	flagSystem    = flag.String("system", "README.txt", "A system-owned file present on the server")
	flagThreshold = flag.Int64("threshold", 1048576, "Contributor threshold bytes")
	flagNoAuth    = flag.Bool("noauth", true, "Run noClientAuth suite")
	flagExplorer  = flag.String("explorer", "", "Explorer base URL (optional), e.g. http://127.0.0.1:8081")
	flagVerbose   = flag.Bool("v", false, "Verbose error detail")
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

func col(c, s string) string { return c + s + ansiReset }

type result struct {
	step, want, got string
	err             error
	skipped         bool
	note            string
}

type suite struct {
	name    string
	results []result
}

func (s *suite) check(step, want string, err error, note ...string) {
	got := "ok"
	if err != nil {
		got = "fail"
	}
	s.results = append(s.results, result{
		step: step, want: want, got: got, err: err,
		note: strings.Join(note, " "),
	})
}

func (s *suite) skip(step, reason string) {
	s.results = append(s.results, result{step: step, want: "ok", skipped: true, note: reason})
}

func (s *suite) print() {
	fmt.Printf("\n%s%s%s\n", ansiBold+ansiCyan, s.name, ansiReset)
	fmt.Println(strings.Repeat("─", 74))
	pass, fail, skip := 0, 0, 0
	for i, r := range s.results {
		num := fmt.Sprintf("%2d. ", i+1)
		if r.skipped {
			skip++
			fmt.Printf("  %s%s%-46s%s  %s\n", ansiGray, num, r.step, ansiReset, col(ansiYellow, "SKIP  "+r.note))
			continue
		}
		match := r.want == r.got
		if match {
			pass++
		} else {
			fail++
		}
		status := col(ansiGreen, "PASS")
		if !match {
			status = col(ansiRed, "FAIL")
		}
		wantTag := col(ansiGray, fmt.Sprintf("(want %-4s) ", r.want))
		errStr := ""
		if r.err != nil && (*flagVerbose || !match) {
			errStr = col(ansiGray, "  ← "+trunc(r.err.Error(), 68))
		}
		noteStr := ""
		if r.note != "" {
			noteStr = col(ansiYellow, "  ["+r.note+"]")
		}
		fmt.Printf("  %s  %s%s%s%s%s\n", status, wantTag, ansiGray+num+ansiReset, r.step, errStr, noteStr)
	}
	fmt.Println(strings.Repeat("─", 74))
	total := pass + fail + skip
	summary := fmt.Sprintf("  %d/%d passed", pass, total-skip)
	if fail == 0 {
		fmt.Println(col(ansiGreen, summary))
	} else {
		fmt.Println(col(ansiRed, summary+fmt.Sprintf("  (%d failed)", fail)))
	}
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// tempKey generates a fresh throwaway ECDSA P-256 key each call → distinct user identity.
func tempKey() (ssh.AuthMethod, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", err
	}
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	return ssh.PublicKeys(signer), fp[:16], nil
}

// randUserPass returns keyboard-interactive auth with a unique random password.
// The server hashes (user+password) for identity, so each call is a distinct user.
func randUserPass() (ssh.AuthMethod, string) {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	pw := fmt.Sprintf("testpw-%x", b)
	method := ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = pw
		}
		return answers, nil
	})
	return method, "kbint:" + pw[:14]
}

func hkCB() ssh.HostKeyCallback {
	if *flagHostKey == "" {
		return ssh.InsecureIgnoreHostKey() //nolint:gosec
	}
	data, err := os.ReadFile(*flagHostKey)
	if err != nil {
		fatalf("cannot read host key %s: %v", *flagHostKey, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		fatalf("cannot parse host key: %v", err)
	}
	return ssh.FixedHostKey(pub)
}

func sshCfg(auth ssh.AuthMethod) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: "anonymous", Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: hkCB(), Timeout: 15 * time.Second,
	}
}

func dialSSH(cfg *ssh.ClientConfig) (*ssh.Client, error) {
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", *flagHost, *flagPort), cfg)
}

func openSFTP(auth ssh.AuthMethod) (*ssh.Client, *sftp.Client, error) {
	sshCli, err := dialSSH(sshCfg(auth))
	if err != nil {
		return nil, nil, fmt.Errorf("ssh dial: %w", err)
	}
	sftpCli, err := sftp.NewClient(sshCli)
	if err != nil {
		sshCli.Close()
		return nil, nil, fmt.Errorf("sftp subsystem: %w", err)
	}
	return sshCli, sftpCli, nil
}

// openSFTPNoAuth uses empty Auth so the library sends "none" — accepted when server has -noauth.
func openSFTPNoAuth() (*ssh.Client, *sftp.Client, error) {
	addr := fmt.Sprintf("%s:%d", *flagHost, *flagPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User: "anonymous", Auth: []ssh.AuthMethod{},
		HostKeyCallback: hkCB(), Timeout: 15 * time.Second,
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
		return nil, nil, fmt.Errorf("sftp subsystem: %w", err)
	}
	return sshCli, sftpCli, nil
}

// tryExec sends an exec request. sftpguy replies false → always fails.
func tryExec(auth ssh.AuthMethod) error {
	cli, err := dialSSH(sshCfg(auth))
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
	return nil // unexpected success
}

// tryShell opens a shell channel. sftpguy accepts it, writes "SFTP-only", exits.
func tryShell(auth ssh.AuthMethod) error {
	cli, err := dialSSH(sshCfg(auth))
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
		return fmt.Errorf("server closed shell: %s", trunc(buf.String(), 80))
	case <-time.After(3 * time.Second):
		return fmt.Errorf("shell did not close (timeout)")
	}
}

func sftpRead(c *sftp.Client, p string) error {
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

func sftpWrite(c *sftp.Client, p string, data []byte) error {
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

func sftpAppend(c *sftp.Client, p string, data []byte) error {
	f, err := c.OpenFile(path.Clean("/"+p), os.O_WRONLY|os.O_CREATE|os.O_APPEND)
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

func sftpReadBytes(c *sftp.Client, p string) ([]byte, error) {
	f, err := c.Open(path.Clean("/" + p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func sftpCheckContent(c *sftp.Client, p string, want []byte) error {
	got, err := sftpReadBytes(c, p)
	if err != nil {
		return fmt.Errorf("read %s: %w", p, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("content mismatch for %s (got %q want %q)", p, trunc(string(got), 80), trunc(string(want), 80))
	}
	return nil
}

func randSuffix() string {
	b := make([]byte, 4)
	rand.Read(b) //nolint:errcheck
	return fmt.Sprintf("%08x", binary.BigEndian.Uint32(b))
}

func payload(n int64) []byte {
	if n <= 0 {
		return []byte("hello from sftpguy test client\n")
	}
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck
	return b
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, col(ansiRed, "FATAL: ")+format+"\n", args...)
	os.Exit(1)
}

// runNonOwnerSuite runs the 17-step sequence for a user who does NOT own preexisting.txt.
// Pass auth=nil to use the noClientAuth dial path.
func runNonOwnerSuite(label, preexisting string, auth ssh.AuthMethod) *suite {
	s := &suite{name: label}
	isNoAuth := auth == nil
	sfx := randSuffix()
	newFile := "testclient_new_" + sfx + ".txt"
	renamedFile := "testclient_new_" + sfx + ".renamed.txt"

	probeAuth := auth
	if isNoAuth {
		probeAuth, _ = randUserPass() // exec/shell need some auth method
	}

	// 1. exec
	s.check("exec to server", "fail", tryExec(probeAuth))
	// 2. shell
	s.check("shell to server", "fail", tryShell(probeAuth))

	// 3. connect (SFTP)
	var sshCli *ssh.Client
	var sftpCli *sftp.Client
	var err error
	if isNoAuth {
		sshCli, sftpCli, err = openSFTPNoAuth()
	} else {
		sshCli, sftpCli, err = openSFTP(auth)
	}
	s.check("connect to server (SFTP)", "ok", err)
	if err != nil {
		for i := 0; i < 14; i++ {
			s.skip("(skipped)", "no SFTP connection")
		}
		return s
	}
	defer sshCli.Close()
	defer sftpCli.Close()

	// 4. list /
	_, err = sftpCli.ReadDir("/")
	s.check("list directory /", "ok", err)

	// 5–8: preexisting.txt operations (owned by first, we are not contributor yet)
	s.check("read preexisting.txt", "fail", sftpRead(sftpCli, preexisting))
	s.check("rename preexisting.txt", "fail", sftpCli.Rename(preexisting, preexisting+".bak"))
	s.check("update preexisting.txt", "fail", sftpWrite(sftpCli, preexisting, []byte("overwrite")))
	s.check("delete preexisting.txt", "fail", sftpCli.Remove(preexisting))

	// 9. write new.txt — crosses contributor threshold
	s.check("write new.txt", "ok", sftpWrite(sftpCli, newFile, payload(*flagThreshold)))

	// 10. read preexisting — now contributor
	s.check("read preexisting.txt (contributor)", "ok", sftpRead(sftpCli, preexisting))

	// 11. rename new.txt (own file)
	renErr := sftpCli.Rename(newFile, renamedFile)
	s.check("rename new.txt", "ok", renErr)
	if renErr != nil {
		renamedFile = newFile
	}

	// 12. update new.txt (renamed)
	s.check("update new.txt (renamed)", "ok", sftpWrite(sftpCli, renamedFile, []byte("updated")))

	// 13. delete new.txt
	s.check("delete new.txt", "ok", sftpCli.Remove(renamedFile))

	// 14. read preexisting — still contributor
	s.check("read preexisting.txt (post-cleanup)", "ok", sftpRead(sftpCli, preexisting))

	// 15–17: still cannot touch first's file
	s.check("rename preexisting.txt (post upload)", "fail", sftpCli.Rename(preexisting, preexisting+".bak2"))
	s.check("update preexisting.txt (post upload)", "fail", sftpWrite(sftpCli, preexisting, []byte("overwrite 2")))
	s.check("delete preexisting.txt (post upload)", "fail", sftpCli.Remove(preexisting))

	return s
}

func runResumeSuite(label string, auth ssh.AuthMethod) *suite {
	s := &suite{name: "Resume uploads: " + label}
	sfx := randSuffix()

	sshCli, sftpCli, err := openSFTP(auth)
	s.check("connect to server (SFTP)", "ok", err)
	if err != nil {
		for i := 0; i < 9; i++ {
			s.skip("(skipped)", "no SFTP connection")
		}
		return s
	}
	defer sshCli.Close()
	defer sftpCli.Close()

	// Single file resume (`reput`) behavior.
	resumeFile := "testclient_resume_" + sfx + ".txt"
	initial := []byte("initial contents\n")
	appended := []byte("updated contents\n")
	updated := append(append([]byte{}, initial...), appended...)

	s.check("write initial file", "ok", sftpWrite(sftpCli, resumeFile, initial))
	s.check("resume upload append (reput)", "ok", sftpAppend(sftpCli, resumeFile, appended))
	s.check("verify resumed file contents", "ok", sftpCheckContent(sftpCli, resumeFile, updated))

	// Missing single-file case: `reput` preflight stat fails, then fallback create.
	missingResumeFile := "testclient_resume_missing_" + sfx + ".txt"
	missingResumeFull := []byte("new file sent during resume\n")
	_, statErr := sftpCli.Stat(path.Clean("/" + missingResumeFile))
	s.check("stat missing file (reput preflight)", "fail", statErr)
	s.check("resume missing file fallback create (put)", "ok", sftpWrite(sftpCli, missingResumeFile, missingResumeFull))
	s.check("verify missing resumed file contents", "ok", sftpCheckContent(sftpCli, missingResumeFile, missingResumeFull))

	// Recursive resume (`reput -r`) behavior with mixed existing + missing files.
	baseDir := "testclient_resume_dir_" + sfx
	existingFile := path.Join(baseDir, "root.txt")
	missingFile := path.Join(baseDir, "nested", "child.txt")

	existingInitial := []byte("root-v1\n")
	existingAppended := []byte("root-v2\n")
	existingUpdated := append(append([]byte{}, existingInitial...), existingAppended...)

	missingFull := []byte("child-v1\nchild-v2\n")

	s.check("write initial folder file root.txt", "ok", sftpWrite(sftpCli, existingFile, existingInitial))
	_, statErr = sftpCli.Stat(path.Clean("/" + missingFile))
	s.check("stat missing folder file (reput -r preflight)", "fail", statErr)
	s.check("resume folder upload existing root.txt (reput -r)", "ok", sftpAppend(sftpCli, existingFile, existingAppended))
	s.check("resume folder upload missing child.txt fallback create (put)", "ok", sftpWrite(sftpCli, missingFile, missingFull))
	s.check("verify resumed folder existing root.txt", "ok", sftpCheckContent(sftpCli, existingFile, existingUpdated))
	s.check("verify resumed folder missing child.txt", "ok", sftpCheckContent(sftpCli, missingFile, missingFull))

	return s
}

func runSystemFileSuite(auth ssh.AuthMethod) *suite {
	s := &suite{name: fmt.Sprintf("System file protection (%s)", *flagSystem)}
	sshCli, sftpCli, err := openSFTP(auth)
	s.check("connect to server (SFTP)", "ok", err)
	if err != nil {
		s.skip("rename system file", "no connection")
		s.skip("update system file", "no connection")
		s.skip("delete system file", "no connection")
		return s
	}
	defer sshCli.Close()
	defer sftpCli.Close()
	s.check("rename "+*flagSystem, "fail", sftpCli.Rename(*flagSystem, *flagSystem+".bak"))
	s.check("update "+*flagSystem, "fail", sftpWrite(sftpCli, *flagSystem, []byte("overwrite system")))
	s.check("delete "+*flagSystem, "fail", sftpCli.Remove(*flagSystem))
	return s
}

func runOwnerCleanupSuite(firstAuth ssh.AuthMethod, preexisting string) *suite {
	s := &suite{name: "Owner cleanup (first user)"}
	sshCli, sftpCli, err := openSFTP(firstAuth)
	s.check("connect as first", "ok", err)
	if err != nil {
		s.skip("rename preexisting.txt", "no connection")
		s.skip("update preexisting.txt", "no connection")
		s.skip("delete preexisting.txt", "no connection")
		return s
	}
	defer sshCli.Close()
	defer sftpCli.Close()

	// Rename to tmp and back to confirm round-trip
	tmp := preexisting + ".tmp"
	renErr := sftpCli.Rename(preexisting, tmp)
	s.check("rename preexisting.txt", "ok", renErr)
	if renErr == nil {
		_ = sftpCli.Rename(tmp, preexisting)
	}
	s.check("update preexisting.txt", "ok", sftpWrite(sftpCli, preexisting, []byte("updated by owner")))
	s.check("delete preexisting.txt", "ok", sftpCli.Remove(preexisting))
	return s
}

func runExplorerSuite(baseURL, preexisting string) *suite {
	s := &suite{name: "Explorer HTTP permissions"}
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		s.skip("explorer suite", "no -explorer URL provided")
		return s
	}

	clientA, err := tcHTTPClient()
	s.check("client A init", "ok", err)
	if err != nil {
		return s
	}
	clientB, err := tcHTTPClient()
	s.check("client B init", "ok", err)
	if err != nil {
		return s
	}

	status, body, err := tcExplorerGET(clientA, strings.TrimRight(baseURL, "/")+"/")
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("bootstrap status %d", status)
	}
	s.check("bootstrap explorer (A)", "ok", err)
	if err != nil {
		return s
	}

	csrf, err := tcExplorerCSRF(body)
	s.check("extract csrf token (A)", "ok", err)
	if err != nil {
		return s
	}

	status, _, err = tcExplorerGET(clientA, strings.TrimRight(baseURL, "/")+"/"+preexisting)
	if err == nil && status != http.StatusForbidden {
		err = fmt.Errorf("expected 403 before contributing, got %d", status)
	}
	s.check("download locked file blocked (A)", "ok", err)

	err = tcExplorerUpload(clientA, strings.TrimRight(baseURL, "/")+"/", csrf, "testclient_explorer_"+randSuffix()+".bin", payload(*flagThreshold))
	s.check("upload via explorer (A)", "ok", err)
	if err != nil {
		return s
	}

	status, _, err = tcExplorerGET(clientA, strings.TrimRight(baseURL, "/")+"/"+preexisting)
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("expected 200 after contributing, got %d", status)
	}
	s.check("download locked file allowed (A)", "ok", err)

	status, _, err = tcExplorerGET(clientB, strings.TrimRight(baseURL, "/")+"/"+preexisting)
	if err == nil && status != http.StatusForbidden {
		err = fmt.Errorf("expected 403 for separate client, got %d", status)
	}
	s.check("download still blocked (B)", "ok", err)

	u, _ := url.Parse(baseURL)
	idCookie := ""
	for _, c := range clientA.Jar.Cookies(u) {
		if strings.Contains(c.Name, "_id") {
			idCookie = c.Name
			break
		}
	}
	if idCookie == "" {
		s.check("tamper identity cookie", "ok", fmt.Errorf("identity cookie not found"))
		return s
	}
	clientA.Jar.SetCookies(u, []*http.Cookie{{
		Name:  idCookie,
		Value: "v1.tampered.bad-signature",
		Path:  "/",
	}})
	status, _, err = tcExplorerGET(clientA, strings.TrimRight(baseURL, "/")+"/"+preexisting)
	if err == nil && status != http.StatusForbidden {
		err = fmt.Errorf("expected 403 after tampering cookie, got %d", status)
	}
	s.check("tampered identity loses access (A)", "ok", err)

	return s
}

func tcHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{Jar: jar}, nil
}

func tcExplorerGET(client *http.Client, rawURL string) (status int, body string, err error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), nil
}

func tcExplorerCSRF(html string) (string, error) {
	re := regexp.MustCompile(`value=\"([a-f0-9]{64})\"`)
	m := re.FindStringSubmatch(html)
	if len(m) != 2 {
		return "", fmt.Errorf("csrf token not found")
	}
	return m[1], nil
}

func tcExplorerUpload(client *http.Client, postURL, csrfToken, filename string, data []byte) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("csrf_token", csrfToken); err != nil {
		return err
	}
	fw, err := mw.CreateFormFile("uploadFiles", filename)
	if err != nil {
		return err
	}
	if _, err := fw.Write(data); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, postURL, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

func main() {
	flag.Parse()

	fmt.Printf("%ssftpguy integration test client%s\n", ansiBold, ansiReset)
	fmt.Printf("  server:    %s:%d\n", *flagHost, *flagPort)
	fmt.Printf("  system:    %s\n", *flagSystem)
	fmt.Printf("  threshold: %s\n", humanBytes(*flagThreshold))
	fmt.Println()

	firstAuth, firstLabel, err := tempKey()
	if err != nil {
		fatalf("generate first key: %v", err)
	}
	secondAuth, secondLabel, err := tempKey()
	if err != nil {
		fatalf("generate second key: %v", err)
	}
	kbAuth, kbLabel := randUserPass()

	fmt.Printf("  first  (file owner): pubkey %s\n", firstLabel)
	fmt.Printf("  second (non-owner):  pubkey %s\n", secondLabel)
	fmt.Printf("  kbint  (non-owner):  %s\n", kbLabel)
	fmt.Println()

	// Setup: first writes preexisting.txt
	preexisting := "preexisting_" + randSuffix() + ".txt"
	fmt.Printf("%s── Setup%s  writing %q as first…  ", ansiBold, ansiReset, preexisting)

	setupSuite := &suite{name: "Setup"}
	{
		sshCli, sftpCli, err := openSFTP(firstAuth)
		setupSuite.check("connect as first", "ok", err)
		if err != nil {
			setupSuite.print()
			fatalf("cannot connect as first: %v", err)
		}
		writeErr := sftpWrite(sftpCli, preexisting, payload(*flagThreshold))
		setupSuite.check("write preexisting.txt as first", "ok", writeErr)
		sftpCli.Close()
		sshCli.Close()
		if writeErr != nil {
			setupSuite.print()
			fatalf("could not write %s: %v", preexisting, writeErr)
		}
	}
	fmt.Println(col(ansiGreen, "ok"))

	suites := []*suite{setupSuite}
	suites = append(suites, runNonOwnerSuite(
		fmt.Sprintf("Non-owner: second (pubkey %s)", secondLabel), preexisting, secondAuth))
	suites = append(suites, runNonOwnerSuite(
		fmt.Sprintf("Non-owner: %s", kbLabel), preexisting, kbAuth))
	if *flagNoAuth {
		suites = append(suites, runNonOwnerSuite(
			"Non-owner: noClientAuth (anonymous-by-IP)", preexisting, nil))
	}
	suites = append(suites, runResumeSuite(
		fmt.Sprintf("second (pubkey %s)", secondLabel), secondAuth))
	suites = append(suites, runSystemFileSuite(secondAuth))
	suites = append(suites, runExplorerSuite(*flagExplorer, preexisting))
	suites = append(suites, runOwnerCleanupSuite(firstAuth, preexisting))

	totalPass, totalFail, totalSkip := 0, 0, 0
	for _, s := range suites {
		s.print()
		for _, r := range s.results {
			if r.skipped {
				totalSkip++
			} else if r.want == r.got {
				totalPass++
			} else {
				totalFail++
			}
		}
	}

	fmt.Printf("\n%sOverall: %d passed, %d failed, %d skipped%s\n\n",
		ansiBold, totalPass, totalFail, totalSkip, ansiReset)
	if totalFail > 0 {
		os.Exit(1)
	}
}
