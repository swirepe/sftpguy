package socketactivation

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const firstSystemdFD = 3

type Listener struct {
	Name     string
	Listener net.Listener
}

var (
	listenersOnce sync.Once
	listeners     []Listener
	listenersErr  error
)

func Listeners() ([]Listener, error) {
	listenersOnce.Do(loadListeners)
	if listenersErr != nil {
		return nil, listenersErr
	}
	out := make([]Listener, len(listeners))
	copy(out, listeners)
	return out, nil
}

func ListenerByName(names ...string) (net.Listener, bool, error) {
	ls, err := Listeners()
	if err != nil {
		return nil, false, err
	}
	l, ok := listenerByNameFrom(ls, names...)
	return l, ok, nil
}

func ListenerByNameOrIndex(name string, fallbackIndex int) (net.Listener, bool, error) {
	ls, err := Listeners()
	if err != nil {
		return nil, false, err
	}
	l, ok := listenerByNameOrIndexFrom(ls, name, fallbackIndex)
	return l, ok, nil
}

func ListenerByNameOrNetwork(name string, fallbackNetworks ...string) (net.Listener, bool, error) {
	ls, err := Listeners()
	if err != nil {
		return nil, false, err
	}
	l, ok := listenerByNameOrNetworkFrom(ls, name, fallbackNetworks...)
	return l, ok, nil
}

func listenerByNameFrom(ls []Listener, names ...string) (net.Listener, bool) {
	if len(ls) == 0 {
		return nil, false
	}

	requestedName := false
	for _, want := range names {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		requestedName = true
		for _, l := range ls {
			if l.Name == want {
				return l.Listener, true
			}
		}
	}

	if len(ls) == 1 && !requestedName {
		return ls[0].Listener, true
	}
	return nil, false
}

func listenerByNameOrIndexFrom(ls []Listener, name string, fallbackIndex int) (net.Listener, bool) {
	if l, ok := listenerByNameFrom(ls, name); ok {
		return l, true
	}
	if fallbackIndex < 0 || fallbackIndex >= len(ls) {
		return nil, false
	}
	if strings.TrimSpace(ls[fallbackIndex].Name) != "" {
		return nil, false
	}
	return ls[fallbackIndex].Listener, true
}

func listenerByNameOrNetworkFrom(ls []Listener, name string, fallbackNetworks ...string) (net.Listener, bool) {
	if l, ok := listenerByNameFrom(ls, name); ok {
		return l, true
	}
	wants := make(map[string]bool, len(fallbackNetworks))
	for _, network := range fallbackNetworks {
		network = strings.TrimSpace(network)
		if network != "" {
			wants[network] = true
		}
	}
	if len(wants) == 0 {
		return nil, false
	}
	var match net.Listener
	for _, l := range ls {
		if strings.TrimSpace(l.Name) != "" {
			continue
		}
		addr := l.Listener.Addr()
		if addr == nil || !wants[addr.Network()] {
			continue
		}
		if match != nil {
			return nil, false
		}
		match = l.Listener
	}
	return match, match != nil
}

func loadListeners() {
	n, err := listenFDCount()
	if err != nil || n == 0 {
		listenersErr = err
		return
	}

	names := listenFDNames(n)
	for i := 0; i < n; i++ {
		fd := uintptr(firstSystemdFD + i)
		name := names[i]
		file := os.NewFile(fd, fmt.Sprintf("systemd-listen-fd-%d", fd))
		if file == nil {
			listenersErr = fmt.Errorf("systemd fd %d unavailable", fd)
			return
		}
		l, err := net.FileListener(file)
		_ = file.Close()
		if err != nil {
			listenersErr = fmt.Errorf("systemd fd %d (%s): %w", fd, name, err)
			return
		}
		listeners = append(listeners, Listener{Name: name, Listener: l})
	}
}

func listenFDCount() (int, error) {
	rawPID := strings.TrimSpace(os.Getenv("LISTEN_PID"))
	rawFDs := strings.TrimSpace(os.Getenv("LISTEN_FDS"))
	if rawPID == "" || rawFDs == "" {
		return 0, nil
	}

	pid, err := strconv.Atoi(rawPID)
	if err != nil {
		return 0, fmt.Errorf("invalid LISTEN_PID %q: %w", rawPID, err)
	}
	if pid != os.Getpid() {
		return 0, nil
	}

	n, err := strconv.Atoi(rawFDs)
	if err != nil {
		return 0, fmt.Errorf("invalid LISTEN_FDS %q: %w", rawFDs, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid LISTEN_FDS %q: must be >= 0", rawFDs)
	}
	return n, nil
}

func listenFDNames(n int) []string {
	out := make([]string, n)
	raw := strings.TrimSpace(os.Getenv("LISTEN_FDNAMES"))
	if raw == "" {
		return out
	}
	for i, name := range strings.Split(raw, ":") {
		if i >= n {
			break
		}
		out[i] = name
	}
	return out
}
