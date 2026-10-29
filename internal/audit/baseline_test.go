package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func finding(severity, message string) Finding {
	return Finding{Severity: severity, Message: message}
}

func TestCompare(t *testing.T) {
	t.Parallel()

	// Findings are deliberately inserted out of order to verify stable sorting.
	baseline := &Report{
		Secrets: map[string]SecretReport{
			"shared": {
				Name: "shared",
				Findings: map[string]Finding{
					"msg-only":      finding("warning", "old message"),
					"sev-change":    finding("warning", "getting worse"),
					"hibp":          finding("warning", "found in breach"),
					"gone-analyzer": finding("warning", "no longer reported"),
					"same":          finding("error", "same severity"),
					"crunchy":       finding("warning", "weak"),
					"equals-name":   finding("none", "ok"),
					"all-good":      finding("none", "ok"),
				},
			},
			"gone": {
				Name: "gone",
				Findings: map[string]Finding{
					"crunchy": finding("warning", "not scanned anymore"),
				},
			},
		},
	}

	current := &Report{
		Secrets: map[string]SecretReport{
			"shared": {
				Name: "shared",
				Findings: map[string]Finding{
					// resolved: was a warning, now explicitly none.
					"crunchy": finding("none", "ok"),
					// new: was none, now a warning.
					"equals-name": finding("warning", "password equals name"),
					// severity change warning -> error.
					"hibp": finding("error", "found in many breaches"),
					// new analyzer with a real finding.
					"newone": finding("warning", "freshly flagged"),
					// message only change must be ignored.
					"msg-only": finding("warning", "new message"),
					// severity change warning -> error.
					"sev-change": finding("error", "got worse"),
					// unchanged severity despite a different message.
					"same": finding("error", "a different message"),
					// none on both sides.
					"all-good": finding("none", "ok"),
					// "gone-analyzer" is absent, i.e. the finding disappeared.
				},
			},
			"fresh": {
				Name: "fresh",
				Findings: map[string]Finding{
					"crunchy": finding("none", "ok"),
				},
			},
		},
	}

	cmp := Compare(baseline, current, "baseline.json")
	require.NotNil(t, cmp)

	assert.Equal(t, "baseline.json", cmp.Path)
	assert.Equal(t, []string{"fresh"}, cmp.SecretsAdded)
	assert.Equal(t, []string{"gone"}, cmp.SecretsRemoved)

	want := []FindingChange{
		{Secret: "shared", Analyzer: "crunchy", Change: ChangeResolved, SeverityBefore: "warning"},
		{Secret: "shared", Analyzer: "equals-name", Change: ChangeNew, SeverityAfter: "warning"},
		{Secret: "shared", Analyzer: "gone-analyzer", Change: ChangeResolved, SeverityBefore: "warning"},
		{Secret: "shared", Analyzer: "hibp", Change: ChangeSeverityChanged, SeverityBefore: "warning", SeverityAfter: "error"},
		{Secret: "shared", Analyzer: "newone", Change: ChangeNew, SeverityAfter: "warning"},
		{Secret: "shared", Analyzer: "sev-change", Change: ChangeSeverityChanged, SeverityBefore: "warning", SeverityAfter: "error"},
	}
	assert.Equal(t, want, cmp.Findings)
}

func TestCompareEmptyAndNil(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		name     string
		baseline *Report
		current  *Report
	}{
		{"both nil", nil, nil},
		{"empty reports", &Report{}, &Report{}},
	} {
		cmp := Compare(c.baseline, c.current, "b.json")
		require.NotNil(t, cmp)
		assert.Empty(t, cmp.SecretsAdded)
		assert.Empty(t, cmp.SecretsRemoved)
		assert.Empty(t, cmp.Findings)
		// slices must be non-nil so the JSON schema always renders arrays.
		assert.NotNil(t, cmp.SecretsAdded)
		assert.NotNil(t, cmp.SecretsRemoved)
		assert.NotNil(t, cmp.Findings)
	}
}

func TestLoadBaseline(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	t.Run("valid report round trip", func(t *testing.T) {
		report := &Report{
			Secrets: map[string]SecretReport{
				"foo": {
					Name: "foo",
					Findings: map[string]Finding{
						"crunchy":     finding("warning", "weak password"),
						"equals-name": finding("none", "ok"),
					},
				},
				// a secret without any findings key (omitted in JSON) is valid.
				"empty": {Name: "empty"},
			},
		}

		fn := filepath.Join(dir, "valid.json")
		fh, err := os.Create(fn)
		require.NoError(t, err)
		require.NoError(t, report.RenderJSON(fh))
		require.NoError(t, fh.Close())

		loaded, err := LoadBaseline(fn)
		require.NoError(t, err)
		require.Contains(t, loaded.Secrets, "foo")
		assert.Equal(t, "warning", loaded.Secrets["foo"].Findings["crunchy"].Severity)
		assert.Contains(t, loaded.Secrets, "empty")
		assert.Nil(t, loaded.Secrets["empty"].Findings)
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadBaseline(filepath.Join(dir, "does-not-exist.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read baseline report")
	})

	mustWrite := func(t *testing.T, name, content string) string {
		t.Helper()
		fn := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(fn, []byte(content), 0o600))

		return fn
	}

	t.Run("invalid JSON", func(t *testing.T) {
		fn := mustWrite(t, "broken.json", "{not json")
		_, err := LoadBaseline(fn)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valid JSON")
	})

	t.Run("missing secrets field", func(t *testing.T) {
		fn := mustWrite(t, "no-secrets.json", `{"duration":"1s"}`)
		_, err := LoadBaseline(fn)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing the required field \"secrets\"")
	})

	t.Run("finding missing severity", func(t *testing.T) {
		fn := mustWrite(t, "no-severity.json", `{
			"duration": "1s",
			"secrets": {
				"foo": {"name": "foo", "findings": {"crunchy": {"message": "ok"}}}
			}
		}`)
		_, err := LoadBaseline(fn)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing the required field \"severity\"")
	})

	t.Run("finding severity wrong type", func(t *testing.T) {
		fn := mustWrite(t, "bad-type.json", `{
			"duration": "1s",
			"secrets": {
				"foo": {"name": "foo", "findings": {"crunchy": {"severity": 123}}}
			}
		}`)
		_, err := LoadBaseline(fn)
		require.Error(t, err)
	})

	t.Run("empty secrets object is valid", func(t *testing.T) {
		fn := mustWrite(t, "empty-secrets.json", `{"duration":"1s","secrets":{}}`)
		loaded, err := LoadBaseline(fn)
		require.NoError(t, err)
		assert.Empty(t, loaded.Secrets)
	})
}

func TestRenderJSONWithBaseline(t *testing.T) {
	t.Parallel()

	report := &Report{
		Secrets: map[string]SecretReport{
			"foo": {
				Name:     "foo",
				Findings: map[string]Finding{"crunchy": finding("warning", "weak")},
			},
		},
		Baseline: &BaselineComparison{
			Path:           "old.json",
			SecretsAdded:   []string{"foo"},
			SecretsRemoved: []string{},
			Findings: []FindingChange{
				{Secret: "foo", Analyzer: "crunchy", Change: ChangeNew, SeverityAfter: "warning"},
			},
		},
	}

	buf := &bytes.Buffer{}
	require.NoError(t, report.RenderJSON(buf))

	var payload struct {
		Duration string `json:"duration"`
		Secrets  map[string]struct {
			Name     string             `json:"name"`
			Findings map[string]Finding `json:"findings"`
		} `json:"secrets"`
		Baseline *BaselineComparison `json:"baseline"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	// the full current report is preserved.
	require.Contains(t, payload.Secrets, "foo")
	assert.Equal(t, "warning", payload.Secrets["foo"].Findings["crunchy"].Severity)

	// the comparison section is present.
	require.NotNil(t, payload.Baseline)
	assert.Equal(t, "old.json", payload.Baseline.Path)
	assert.Equal(t, []string{"foo"}, payload.Baseline.SecretsAdded)
	require.Len(t, payload.Baseline.Findings, 1)
	assert.Equal(t, ChangeNew, payload.Baseline.Findings[0].Change)

	// no password material is ever part of the report types.
	assert.NotContains(t, buf.String(), "supersecret-plaintext")
}

func TestRenderJSONWithoutBaselineOmitsKey(t *testing.T) {
	t.Parallel()

	report := &Report{Secrets: map[string]SecretReport{}}
	buf := &bytes.Buffer{}
	require.NoError(t, report.RenderJSON(buf))
	assert.NotContains(t, buf.String(), "baseline")
}
