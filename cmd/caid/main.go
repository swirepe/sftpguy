package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"sftpguy/caid"
)

const jobBufferPerWorker = 4

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := run(os.Args[1:], logger, os.Stderr); err != nil {
		logger.Print(err)
		os.Exit(1)
	}
}

func run(args []string, logger *log.Logger, stderr io.Writer) error {
	flagSet := flag.NewFlagSet("caid", flag.ContinueOnError)
	flagSet.SetOutput(stderr)
	var verbose bool
	workers := defaultWorkerCount()
	flagSet.BoolVar(&verbose, "v", false, "Show additional match metadata")
	flagSet.BoolVar(&verbose, "verbose", false, "Show additional match metadata")
	flagSet.IntVar(&workers, "workers", workers, "Number of concurrent file-matching workers")
	flagSet.Usage = func() {
		fmt.Fprintf(flagSet.Output(), "Usage: %s [flags] <caid.db> <folder>\n", flagSet.Name())
		flagSet.PrintDefaults()
	}
	if err := flagSet.Parse(args); err != nil {
		return err
	}
	if flagSet.NArg() != 2 {
		flagSet.Usage()
		return fmt.Errorf("expected CAID database path and folder to scan")
	}

	dbPath := flagSet.Arg(0)
	root, err := filepath.Abs(flagSet.Arg(1))
	if err != nil {
		return fmt.Errorf("resolve scan root: %w", err)
	}

	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat scan root: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("scan root is not a directory: %s", root)
	}

	if workers < 1 {
		return fmt.Errorf("workers must be >= 1")
	}

	matchers, err := openMatchers(dbPath, workers)
	if err != nil {
		return fmt.Errorf("open CAID matchers: %w", err)
	}
	defer closeMatchers(matchers)

	scanned, matches, err := scan(root, matchers, logger, verbose)
	if err != nil {
		return fmt.Errorf("scan folder: %w", err)
	}

	logger.Printf("scan complete root=%q scanned=%d matches=%d", root, scanned, matches)
	return nil
}

type scanResult struct {
	path    string
	match   caid.Match
	matched bool
	err     error
}

func defaultWorkerCount() int {
	if n := runtime.GOMAXPROCS(0); n > 0 {
		return n
	}
	return 1
}

func openMatchers(dbPath string, workers int) ([]*caid.Matcher, error) {
	matchers := make([]*caid.Matcher, 0, workers)
	for range workers {
		matcher, err := caid.NewMatcherWithOptions(dbPath, caid.MatcherOptions{MaxOpenConns: 1})
		if err != nil {
			_ = closeMatchers(matchers)
			return nil, err
		}
		matchers = append(matchers, matcher)
	}
	return matchers, nil
}

func closeMatchers(matchers []*caid.Matcher) error {
	errs := make([]error, 0, len(matchers))
	for _, matcher := range matchers {
		if matcher == nil {
			continue
		}
		errs = append(errs, matcher.Close())
	}
	return errors.Join(errs...)
}

func scan(root string, matchers []*caid.Matcher, logger *log.Logger, verbose bool) (int, int, error) {
	paths := make(chan string, len(matchers)*jobBufferPerWorker)
	results := make(chan scanResult, len(matchers))

	var workers sync.WaitGroup
	for _, matcher := range matchers {
		matcher := matcher
		workers.Add(1)
		go func() {
			defer workers.Done()
			for path := range paths {
				match, matched, err := matcher.MatchFile(path)
				results <- scanResult{
					path:    path,
					match:   match,
					matched: matched,
					err:     err,
				}
			}
		}()
	}

	walkErrCh := make(chan error, 1)
	go func() {
		defer close(paths)
		walkErrCh <- filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				logger.Printf("walk error path=%q err=%v", path, walkErr)
				return nil
			}
			if d.IsDir() {
				return nil
			}

			paths <- path
			return nil
		})
	}()

	go func() {
		workers.Wait()
		close(results)
	}()

	var scanned int
	var matches int
	for result := range results {
		scanned++
		if result.err != nil {
			logger.Printf("match error path=%q err=%v", result.path, result.err)
			continue
		}
		if !result.matched {
			continue
		}

		matches++
		logMatch(logger, root, result.path, result.match, verbose)
	}

	return scanned, matches, <-walkErrCh
}

func logMatch(logger *log.Logger, root, path string, match caid.Match, verbose bool) {
	relPath := path
	if rel, err := filepath.Rel(root, path); err == nil {
		relPath = rel
	}

	label := match.FormatLabel()
	if verbose {
		logger.Printf(
			"match path=%q label=%q size=%d allzero=%t modtime=%q filetype=%q category=%d md5=%q sha1=%q",
			relPath,
			label,
			match.Size,
			match.IsAllZero,
			match.Info.ModTime().UTC().Format(time.RFC3339Nano),
			match.FileType,
			match.Category,
			match.Md5Hex,
			match.Sha1Hex,
		)
		return
	}
	logger.Printf("match path=%q label=%q", relPath, label)
}
