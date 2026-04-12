package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"

	"sftpguy/caid"
)

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
	flagSet.BoolVar(&verbose, "v", false, "Show additional match metadata")
	flagSet.BoolVar(&verbose, "verbose", false, "Show additional match metadata")
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

	matcher, err := caid.NewMatcher(dbPath)
	if err != nil {
		return fmt.Errorf("open CAID matcher: %w", err)
	}
	defer matcher.Close()

	var scanned int
	var matches int
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			logger.Printf("walk error path=%q err=%v", path, walkErr)
			return nil
		}
		if d.IsDir() {
			return nil
		}

		scanned++

		match, matched, err := matcher.MatchFile(path)
		if err != nil {
			logger.Printf("match error path=%q err=%v", path, err)
			return nil
		}
		if !matched {
			return nil
		}

		relPath := path
		if rel, err := filepath.Rel(root, path); err == nil {
			relPath = rel
		}
		matches++
		label := match.FormatLabel()
		if verbose {
			logger.Printf(
				"match path=%q label=%q size=%d modtime=%q filetype=%q category=%d md5=%q sha1=%q",
				relPath,
				label,
				match.Size,
				match.Info.ModTime().UTC().Format(time.RFC3339Nano),
				match.FileType,
				match.Category,
				match.Md5Hex,
				match.Sha1Hex,
			)
			return nil
		}
		logger.Printf("match path=%q label=%q", relPath, label)
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan folder: %w", err)
	}

	logger.Printf("scan complete root=%q scanned=%d matches=%d", root, scanned, matches)
	return nil
}
