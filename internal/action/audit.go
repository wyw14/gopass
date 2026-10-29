package action

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gopasspw/gopass/internal/action/exit"
	"github.com/gopasspw/gopass/internal/audit"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/internal/tree"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/gopasspw/gopass/pkg/fsutil"
	"github.com/urfave/cli/v3"
)

// Audit validates passwords against common flaws.
func (s *auditHandler) Audit(ctx context.Context, cmd *cli.Command) error {
	ctx = ctxutil.WithGlobalFlags(ctx, cmd)

	_ = s.rem.Reset("audit")
	out.Print(ctx, "Auditing passwords for common flaws ...")

	// The baseline comparison is only supported for JSON output. It is loaded
	// and validated before the (potentially slow) audit runs so we fail fast
	// and never write a report when the baseline cannot be used.
	baselinePath, baselineReport, err := loadAuditBaseline(cmd)
	if err != nil {
		return err
	}

	t, err := s.Store.Tree(ctx)
	if err != nil {
		return exit.Error(exit.List, err, "failed to get store tree: %s", err)
	}

	if filter := cmd.Args().First(); filter != "" {
		subtree, err := t.FindFolder(filter)
		if err != nil {
			return exit.Error(exit.Unknown, err, "failed to find subtree: %s", err)
		}
		debug.Log("subtree for %q: %+v", filter, subtree)
		t = subtree
	}

	list := t.List(tree.INF)

	if len(list) < 1 {
		out.Printf(ctx, "No secrets found")

		return nil
	}

	nList, err := audit.FilteredList(ctx, s.Store)
	if err != nil {
		return exit.Error(exit.List, err, "failed to list secrets: %s", err)
	}
	// if a filter was given, restrict the audit to the matching subtree
	nList = filterAuditList(cmd.Args().First(), list, nList)
	if len(nList) < len(list) {
		out.Warningf(ctx, "Excluding %d secrets based on .gopass-audit-ignore", len(list)-len(nList))
	}

	a := audit.New(ctx, s.Store)
	r, err := a.Batch(ctx, nList)
	if err != nil {
		return exit.Error(exit.Unknown, err, "failed to audit password store: %s", err)
	}

	if p := cmd.String("template"); p != "" && fsutil.IsFile(p) {
		r.Template = p
	}

	switch cmd.String("format") {
	case "html":
		return saveReport(ctx, r.RenderHTML, cmd.String("output-file"), "html")
	case "csv":
		return saveReport(ctx, r.RenderCSV, cmd.String("output-file"), "csv")
	case "json":
		return saveJSONReport(ctx, cmd, r, baselineReport, baselinePath)
	default:
		var err error
		if cmd.Bool("full") {
			debug.Log("Printing full report")
			err = r.PrintResults(ctx)
		}
		if cmd.Bool("summary") {
			debug.Log("Printing summary")

			nerr := r.PrintSummary(ctx)
			// do not overwrite err if it is already set
			if err == nil {
				err = nerr
			}
		}
		if !cmd.Bool("full") && !cmd.Bool("summary") {
			nerr := r.PrintSummary(ctx)
			if err == nil {
				err = nerr
			}
		}

		return err
	}
}

func saveReport(ctx context.Context, f func(io.Writer) error, path, suffix string) error {
	if path == "" {
		out.Noticef(ctx, "No output filename given. Will use a random file name. Use `--output-file` to specify.")
	}

	fn, err := writeReport(f, path)
	if err != nil {
		return exit.Error(exit.Unknown, err, "failed to write report to %s: %s", fn, err)
	}

	if !strings.HasSuffix(fn, "."+suffix) {
		nfn := fn + "." + suffix
		if err := os.Rename(fn, fn+"."+suffix); err != nil {
			return exit.Error(exit.IO, err, "failed to rename report to %s: %s", nfn, err)
		}
		fn = nfn
	}

	out.Noticef(ctx, "Wrote report to %s", fn)

	return nil
}

func writeReport(f func(io.Writer) error, path string) (string, error) {
	fh, err := openReport(path)
	if err != nil {
		return "", err
	}
	defer fh.Close() //nolint:errcheck

	if err := f(fh); err != nil {
		return "", err
	}

	return fh.Name(), nil
}

func openReport(path string) (*os.File, error) {
	if path == "" {
		return os.CreateTemp("", "gopass-report")
	}

	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}

// sameReportPath reports whether the output path points at the same file as
// the baseline report. The baseline file is known to exist, so if both paths
// can be stat'ed we compare the actual files; otherwise we fall back to
// comparing the cleaned absolute paths (case-insensitively on Windows).
func sameReportPath(output, baseline string) (bool, error) {
	absOut, err := filepath.Abs(output)
	if err != nil {
		return false, err
	}

	absBaseline, err := filepath.Abs(baseline)
	if err != nil {
		return false, err
	}

	if fi1, err1 := os.Stat(absOut); err1 == nil {
		if fi2, err2 := os.Stat(absBaseline); err2 == nil && os.SameFile(fi1, fi2) {
			return true, nil
		}
	}

	if runtime.GOOS == "windows" {
		return strings.EqualFold(absOut, absBaseline), nil
	}

	return absOut == absBaseline, nil
}

// loadAuditBaseline loads the report given via --baseline. An empty path
// returns no baseline. The flag is only accepted together with --format json.
func loadAuditBaseline(cmd *cli.Command) (string, *audit.Report, error) {
	baselinePath := cmd.String("baseline")
	if baselinePath == "" {
		return "", nil, nil
	}

	if cmd.String("format") != "json" {
		return "", nil, exit.Error(exit.Usage, nil, "the --baseline flag can only be used together with --format json")
	}

	baselineReport, err := audit.LoadBaseline(baselinePath)
	if err != nil {
		return "", nil, exit.Error(exit.IO, err, "failed to load audit baseline report: %s", err)
	}

	return baselinePath, baselineReport, nil
}

// saveJSONReport attaches the baseline comparison (when requested) and writes
// the JSON report. It refuses to overwrite the baseline file itself.
func saveJSONReport(ctx context.Context, cmd *cli.Command, current, baselineReport *audit.Report, baselinePath string) error {
	if baselineReport != nil {
		if err := rejectBaselineOverwrite(cmd, baselinePath); err != nil {
			return err
		}

		current.Baseline = audit.Compare(baselineReport, current, baselinePath)
	}

	return saveReport(ctx, current.RenderJSON, cmd.String("output-file"), "json")
}

// rejectBaselineOverwrite returns a Usage error when the report would be
// written to the same file as the baseline.
func rejectBaselineOverwrite(cmd *cli.Command, baselinePath string) error {
	outFile := cmd.String("output-file")
	if outFile == "" {
		return nil
	}

	same, err := sameReportPath(outFile, baselinePath)
	if err != nil {
		return exit.Error(exit.IO, err, "failed to check report path: %s", err)
	}

	if same {
		return exit.Error(exit.Usage, nil, "refusing to overwrite the baseline report %q, please choose a different --output-file", baselinePath)
	}

	return nil
}

// filterAuditList restricts the audited secrets to those present in listed
// when a subtree filter was given. Without a filter all audited secrets are
// returned unchanged.
func filterAuditList(filter string, listed, audited []string) []string {
	if filter == "" {
		return audited
	}

	allowed := make(map[string]struct{}, len(listed))
	for _, name := range listed {
		allowed[name] = struct{}{}
	}

	filtered := make([]string, 0, len(audited))
	for _, name := range audited {
		if _, ok := allowed[name]; ok {
			filtered = append(filtered, name)
		}
	}

	return filtered
}
