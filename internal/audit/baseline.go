package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/gopasspw/gopass/pkg/set"
)

// Change types reported for individual findings.
const (
	// ChangeNew marks a finding that is present in the current report but was
	// not present in the baseline.
	ChangeNew = "new"
	// ChangeResolved marks a finding that was present in the baseline but is
	// gone from the current report.
	ChangeResolved = "resolved"
	// ChangeSeverityChanged marks a finding whose severity changed between the
	// baseline and the current report. A message only change is not reported.
	ChangeSeverityChanged = "severity_changed"
)

// FindingChange describes how a single finding, identified by secret name and
// analyzer name, changed between the baseline and the current report.
type FindingChange struct {
	Secret   string `json:"secret"`
	Analyzer string `json:"analyzer"`
	Change   string `json:"change"`
	// SeverityBefore is the baseline severity. Empty for new findings.
	SeverityBefore string `json:"severity_before,omitempty"`
	// SeverityAfter is the current severity. Empty for resolved findings.
	SeverityAfter string `json:"severity_after,omitempty"`
}

// BaselineComparison summarizes how the current report differs from a
// previously recorded JSON baseline report. It never contains any secret
// material, only secret names, analyzer names and severities.
type BaselineComparison struct {
	// Path is the location of the baseline report that was compared against.
	Path string `json:"path"`
	// SecretsAdded lists secret names that only exist in the current report.
	SecretsAdded []string `json:"secrets_added"`
	// SecretsRemoved lists secret names that only exist in the baseline. They
	// were not part of the current audit scope and must not be mistaken for
	// fixed findings.
	SecretsRemoved []string `json:"secrets_removed"`
	// Findings lists the per-finding changes for secrets present in both
	// reports, sorted by secret name and analyzer name.
	Findings []FindingChange `json:"findings"`
}

// LoadBaseline reads and validates a JSON audit report previously written by
// RenderJSON. It only reads the metadata needed for the comparison and never
// touches any secret material (the JSON report does not contain any). It
// returns an error if the file is missing, not valid JSON or if any finding
// record is missing required fields.
func LoadBaseline(filename string) (*Report, error) {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline report %q: %w", filename, err)
	}

	// Decode the top level first so we can tell a missing "secrets" field
	// apart from an empty one and report the precise problem.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(buf, &top); err != nil {
		return nil, fmt.Errorf("baseline report %q does not contain valid JSON: %w", filename, err)
	}

	rawSecrets, found := top["secrets"]
	if !found {
		return nil, fmt.Errorf("baseline report %q is missing the required field %q", filename, "secrets")
	}

	var secrets map[string]SecretReport
	if err := json.Unmarshal(rawSecrets, &secrets); err != nil {
		return nil, fmt.Errorf("baseline report %q does not contain valid JSON: %w", filename, err)
	}

	for name, sec := range secrets {
		if name == "" {
			return nil, fmt.Errorf("baseline report %q contains a secret with an empty name", filename)
		}

		for analyzer, f := range sec.Findings {
			if analyzer == "" {
				return nil, fmt.Errorf("baseline report %q contains a finding for secret %q with an empty analyzer", filename, name)
			}

			if f.Severity == "" {
				return nil, fmt.Errorf("baseline report %q: finding %q for secret %q is missing the required field %q", filename, analyzer, name, "severity")
			}
		}
	}

	return &Report{Secrets: secrets}, nil
}

// Compare computes the differences between the baseline report and the
// current report. Findings are matched by secret name and analyzer name. A
// severity of "none" is not considered a finding. Findings disappearing are
// only evaluated for secrets that are present in both reports; secrets that
// only exist on one side are reported as added or removed instead. The
// result is stably sorted by secret name and analyzer name.
func Compare(baseline, current *Report, baselinePath string) *BaselineComparison {
	cmp := &BaselineComparison{
		Path:           baselinePath,
		SecretsAdded:   []string{},
		SecretsRemoved: []string{},
		Findings:       []FindingChange{},
	}

	if baseline == nil || current == nil {
		return cmp
	}

	for _, name := range set.SortedKeys(current.Secrets) {
		curSec := current.Secrets[name]

		baseSec, found := baseline.Secrets[name]
		if !found {
			cmp.SecretsAdded = append(cmp.SecretsAdded, name)

			continue
		}

		// Findings that existed in the baseline.
		for analyzer, baseFinding := range baseSec.Findings {
			if baseFinding.Severity == "none" {
				continue
			}

			curFinding, present := curSec.Findings[analyzer]
			switch {
			case !present || curFinding.Severity == "none":
				cmp.Findings = append(cmp.Findings, FindingChange{
					Secret:         name,
					Analyzer:       analyzer,
					Change:         ChangeResolved,
					SeverityBefore: baseFinding.Severity,
				})
			case curFinding.Severity != baseFinding.Severity:
				cmp.Findings = append(cmp.Findings, FindingChange{
					Secret:         name,
					Analyzer:       analyzer,
					Change:         ChangeSeverityChanged,
					SeverityBefore: baseFinding.Severity,
					SeverityAfter:  curFinding.Severity,
				})
			}
		}

		// Findings that are new in the current report. A severity only change
		// was already recorded above, so only record the ones the baseline did
		// not have as an actual finding.
		for analyzer, curFinding := range curSec.Findings {
			if curFinding.Severity == "none" {
				continue
			}

			baseFinding, present := baseSec.Findings[analyzer]
			if present && baseFinding.Severity != "none" {
				continue
			}

			cmp.Findings = append(cmp.Findings, FindingChange{
				Secret:        name,
				Analyzer:      analyzer,
				Change:        ChangeNew,
				SeverityAfter: curFinding.Severity,
			})
		}
	}

	for name := range baseline.Secrets {
		if _, found := current.Secrets[name]; !found {
			cmp.SecretsRemoved = append(cmp.SecretsRemoved, name)
		}
	}

	slices.Sort(cmp.SecretsAdded)
	slices.Sort(cmp.SecretsRemoved)
	slices.SortFunc(cmp.Findings, compareChanges)

	return cmp
}

func compareChanges(a, b FindingChange) int {
	if c := strings.Compare(a.Secret, b.Secret); c != 0 {
		return c
	}

	return strings.Compare(a.Analyzer, b.Analyzer)
}
