// Package gate is the human gate (PLAN.md T2.4): the only way a change
// leaves the sandbox. After the run's verdict, while the pod is still
// alive, the harness builds a diff of /workspace against the task's
// original repo and shows it to a person, who answers approve, refuse, or
// defer.
//
// The decision is bound to what was shown: the trace records the SHA-256
// of the exact diff bytes printed. Before an approved patch is written,
// the diff is built again from the pod; if its hash differs, the approval
// is void and nothing is exported.
//
// Without a terminal on stdin the gate always defers: nothing is exported
// unattended. The agent has no tool that reaches this package.
package gate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tushar-patel28/agent-proving-ground/internal/trace"
)

// Decisions, written to trace.Gate.Decision.
const (
	DecisionApproved = "approved" // approved.patch written
	DecisionRefused  = "refused"  // nothing leaves
	DecisionDeferred = "deferred" // pending.patch and its hash written, for later review; nothing applied
	DecisionSkipped  = "skipped"  // no gate: empty diff, or the run failed
	DecisionVoid     = "void"     // approved, but the diff changed (or could not be rebuilt) before export
	DecisionError    = "error"    // the gate itself failed; nothing exported
)

// Shown lists what an interactive approver sees, in order.
var Shown = []string{"diff", "check_result", "check_exit_code", "exit_reason", "diff_sha256_prefix"}

// Config is how the gate talks to the approver and where it writes.
type Config struct {
	In          io.Reader // the approver's answers (the harness's stdin)
	Out         io.Writer // where the diff and the question go (stderr)
	Interactive bool      // stdin is a terminal; if false, the gate always defers
	OutDir      string    // patches go to OutDir/<run_id>/
	Now         func() time.Time
}

// Summary is the run's result, shown next to the diff.
type Summary struct {
	CheckRan   bool
	CheckExit  *int
	Verdict    string
	ExitReason trace.ExitReason
}

// BuildFunc builds the current diff from the pod (kill leftover processes,
// copy /workspace out, Diff against the original repo).
type BuildFunc func(ctx context.Context) ([]byte, error)

func sha(b []byte) string {
	s := sha256.Sum256(b) // [32]byte; s[:] makes it a slice
	return hex.EncodeToString(s[:])
}

// Run runs the gate once and returns its record for the trace.
func Run(ctx context.Context, cfg Config, runID string, sum Summary, build BuildFunc) trace.Gate {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	g := trace.Gate{Interactive: cfg.Interactive, Shown: []string{}}
	// done fills in the decision and the time, and returns the record.
	done := func(decision, reason string) trace.Gate {
		g.Decision, g.Reason, g.DecidedAt = decision, reason, now().UTC()
		return g
	}

	diff, err := build(ctx)
	if err != nil {
		return done(DecisionError, "could not build the diff: "+err.Error())
	}
	if len(diff) == 0 {
		return done(DecisionSkipped, "the diff is empty: nothing in /workspace changed")
	}
	g.DiffSHA256, g.DiffBytes = sha(diff), len(diff)

	if !cfg.Interactive {
		path, err := writePending(cfg.OutDir, runID, diff, g.DiffSHA256)
		if err != nil {
			return done(DecisionError, err.Error())
		}
		g.ExportedPath = path
		return done(DecisionDeferred, "stdin is not a terminal, so the gate defers: nothing is exported unattended")
	}

	show(cfg.Out, runID, diff, g.DiffSHA256, sum)
	g.Shown = Shown
	switch ask(cfg.In, cfg.Out) {
	case DecisionRefused:
		return done(DecisionRefused, "")

	case DecisionApproved:
		// Rebuild from the pod and compare: the approval holds only for
		// the exact bytes that were shown.
		again, err := build(ctx)
		if err != nil {
			return done(DecisionVoid, "approval void: could not rebuild the diff from the pod: "+err.Error())
		}
		g.RecheckSHA256 = sha(again)
		if g.RecheckSHA256 != g.DiffSHA256 {
			return done(DecisionVoid, fmt.Sprintf("approval void: the diff changed after it was shown (sha256 %s shown, %s now); nothing exported",
				g.DiffSHA256[:12], g.RecheckSHA256[:12]))
		}
		path, err := writeNew(filepath.Join(cfg.OutDir, runID), "approved.patch", diff)
		if err != nil {
			return done(DecisionError, err.Error())
		}
		g.ExportedPath = path
		return done(DecisionApproved, "")

	default: // defer, or no valid answer
		path, err := writePending(cfg.OutDir, runID, diff, g.DiffSHA256)
		if err != nil {
			return done(DecisionError, err.Error())
		}
		g.ExportedPath = path
		return done(DecisionDeferred, "")
	}
}

// show prints the diff exactly as it will be exported, then the run's
// result and the start of the diff's hash.
func show(w io.Writer, runID string, diff []byte, hash string, s Summary) {
	fmt.Fprintf(w, "==== apg gate, run %s: diff of /workspace against the task repo ====\n", runID)
	w.Write(diff) // the exact bytes that are hashed and would be exported
	fmt.Fprintln(w, "==== end of diff ====")
	switch {
	case s.CheckRan && s.CheckExit != nil:
		result := "failed"
		if *s.CheckExit == 0 {
			result = "passed"
		}
		fmt.Fprintf(w, "check:       %s (exit code %d)\n", result, *s.CheckExit)
	default:
		fmt.Fprintln(w, "check:       did not run")
	}
	fmt.Fprintf(w, "verdict:     %s\n", s.Verdict)
	fmt.Fprintf(w, "exit reason: %s\n", s.ExitReason)
	fmt.Fprintf(w, "diff sha256: %s (full hash in the trace)\n", hash[:12])
}

// ask reads the answer: approve / refuse / defer (or a / r / d). It asks
// up to three times; end of input or no valid answer means defer.
func ask(r io.Reader, w io.Writer) string {
	in := bufio.NewScanner(r)
	for range 3 { // "range 3" counts 0, 1, 2 (Go 1.22+)
		fmt.Fprint(w, "approve, refuse, or defer? ")
		if !in.Scan() {
			break
		}
		switch strings.ToLower(strings.TrimSpace(in.Text())) {
		case "approve", "a":
			return DecisionApproved
		case "refuse", "r":
			return DecisionRefused
		case "defer", "d":
			return DecisionDeferred
		}
		fmt.Fprintln(w, `please answer "approve", "refuse", or "defer"`)
	}
	fmt.Fprintln(w, "no answer: deferring")
	return DecisionDeferred
}

// writePending writes pending.patch and pending.patch.sha256.
func writePending(outDir, runID string, diff []byte, hash string) (string, error) {
	dir := filepath.Join(outDir, runID)
	path, err := writeNew(dir, "pending.patch", diff)
	if err != nil {
		return "", err
	}
	if _, err := writeNew(dir, "pending.patch.sha256", []byte(hash+"\n")); err != nil {
		return "", err
	}
	return path, nil
}

// writeNew creates dir/name. It never overwrites: O_EXCL makes it fail if
// the file exists.
func writeNew(dir, name string, b []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return "", err
	}
	return path, f.Close()
}

// skipDirs are tool caches, never part of a diff.
var skipDirs = map[string]bool{"__pycache__": true, ".pytest_cache": true}

// entry is one file found in a tree.
type entry struct {
	path    string // full path on the host
	symlink bool
}

// listFiles lists the regular files and symlinks under root by relative path
// ("/"-separated), skipping tool caches.
func listFiles(root string) (map[string]entry, error) {
	out := map[string]entry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir // do not walk into it
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = entry{path: p, symlink: d.Type()&fs.ModeSymlink != 0}
		return nil
	})
	return out, err
}

// Diff returns a unified diff of curDir against origDir, file by file in
// sorted order, with a/ and b/ labels (no timestamps), so the same trees
// always give the same bytes and the result applies with "git apply" or
// "patch -p1". Text files are compared with the host's diff -u (os/exec);
// binary files and symlinks get one line each. Tool caches are skipped.
// An empty result means no change.
func Diff(origDir, curDir string) ([]byte, error) {
	orig, err := listFiles(origDir)
	if err != nil {
		return nil, err
	}
	cur, err := listFiles(curDir)
	if err != nil {
		return nil, err
	}
	// The union of both sets of paths, sorted.
	seen := map[string]bool{}
	var paths []string
	for _, m := range []map[string]entry{orig, cur} {
		for p := range m {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	sort.Strings(paths)

	var out bytes.Buffer
	for _, rel := range paths {
		o, inOrig := orig[rel]
		c, inCur := cur[rel]
		if o.symlink || c.symlink {
			writeSymlinkChange(&out, rel, o, inOrig, c, inCur)
			continue
		}
		oldPath, oldLabel := "/dev/null", "/dev/null"
		if inOrig {
			oldPath, oldLabel = o.path, "a/"+rel
		}
		newPath, newLabel := "/dev/null", "/dev/null"
		if inCur {
			newPath, newLabel = c.path, "b/"+rel
		}
		oldB, err := readOrEmpty(oldPath)
		if err != nil {
			return nil, err
		}
		newB, err := readOrEmpty(newPath)
		if err != nil {
			return nil, err
		}
		if inOrig && inCur && bytes.Equal(oldB, newB) {
			continue
		}
		if isBinary(oldB) || isBinary(newB) {
			fmt.Fprintf(&out, "Binary files %s and %s differ\n", oldLabel, newLabel)
			continue
		}
		d, err := unified(oldPath, oldLabel, newPath, newLabel)
		if err != nil {
			return nil, err
		}
		out.Write(d)
	}
	return out.Bytes(), nil
}

// unified runs "diff -u" on one pair of files.
func unified(oldPath, oldLabel, newPath, newLabel string) ([]byte, error) {
	cmd := exec.Command("diff", "-u", "--label", oldLabel, "--label", newLabel, oldPath, newPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	// diff exits 1 when the files differ: that is the normal case here.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return stdout.Bytes(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("diff %s %s: %v: %s", oldLabel, newLabel, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil // exit 0: no difference
}

func readOrEmpty(p string) ([]byte, error) {
	if p == "/dev/null" {
		return nil, nil
	}
	return os.ReadFile(p)
}

// isBinary uses git's rule of thumb: a NUL byte in the first 8 KiB.
func isBinary(b []byte) bool {
	return bytes.IndexByte(b[:min(len(b), 8<<10)], 0) >= 0
}

// writeSymlinkChange notes a symlink that was added, removed, or changed.
// A patch cannot carry it as a file, so the approver sees a line instead.
func writeSymlinkChange(out *bytes.Buffer, rel string, o entry, inOrig bool, c entry, inCur bool) {
	target := func(e entry, ok bool) string {
		if !ok {
			return "(none)"
		}
		if !e.symlink {
			return "(regular file)"
		}
		t, err := os.Readlink(e.path)
		if err != nil {
			return "(unreadable)"
		}
		return "-> " + t
	}
	was, now := target(o, inOrig), target(c, inCur)
	if was != now {
		fmt.Fprintf(out, "Symlink %s: was %s, now %s\n", rel, was, now)
	}
}
