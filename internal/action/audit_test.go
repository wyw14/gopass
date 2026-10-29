package action

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/gopasspw/gopass/internal/config"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/gopass/secrets"
	"github.com/gopasspw/gopass/tests/gptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAudit(t *testing.T) {
	u := gptest.NewUnitTester(t)

	ctx := config.NewContextInMemory()
	ctx = ctxutil.WithAlwaysYes(ctx, true)
	ctx = ctxutil.WithHidden(ctx, true)
	act, err := newMock(ctx, u.StoreDir(""))
	require.NoError(t, err)
	require.NotNil(t, act)
	ctx = act.cfg.WithConfig(ctx)

	buf := &bytes.Buffer{}
	out.Stdout = buf
	stdout = buf
	defer func() {
		out.Stdout = os.Stdout
		stdout = os.Stdout
	}()

	t.Run("expect audit to complains on very weak passwords", func(t *testing.T) {
		sec := secrets.NewAKV()
		sec.SetPassword("123")
		require.NoError(t, act.Store.Set(ctx, "bar", sec))
		require.NoError(t, act.Store.Set(ctx, "baz", sec))

		require.Error(t, act.Audit(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"full": "true"})), buf.String())
		buf.Reset()
	})

	t.Run("test with filter", func(t *testing.T) {
		c := gptest.CliCtx(ctx, t, "foo")
		require.Error(t, act.Audit(ctx, c))
		buf.Reset()
	})

	t.Run("test empty store", func(t *testing.T) {
		for _, v := range []string{"foo", "bar", "baz"} {
			require.NoError(t, act.Store.Delete(ctx, v))
		}
		require.NoError(t, act.Audit(ctx, gptest.CliCtx(ctx, t)))
		assert.Contains(t, "No secrets found", buf.String())
		buf.Reset()
	})

	t.Run("audit --format json produces valid JSON", func(t *testing.T) {
		sec := secrets.NewAKV()
		sec.SetPassword("hunter2")
		require.NoError(t, act.Store.Set(ctx, "jsontest", sec))
		defer func() { _ = act.Store.Delete(ctx, "jsontest") }()

		outFile := t.TempDir() + "/report.json"
		require.NoError(t, act.Audit(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"format": "json", "output-file": outFile})))
		buf.Reset()

		data, err := os.ReadFile(outFile)
		require.NoError(t, err)
		var report map[string]any
		require.NoError(t, json.Unmarshal(data, &report))
		assert.Contains(t, report, "secrets")
		assert.Contains(t, report, "duration")
	})
}

func TestAuditBaseline(t *testing.T) {
	u := gptest.NewUnitTester(t)

	ctx := config.NewContextInMemory()
	ctx = ctxutil.WithAlwaysYes(ctx, true)
	ctx = ctxutil.WithHidden(ctx, true)
	act, err := newMock(ctx, u.StoreDir(""))
	require.NoError(t, err)
	require.NotNil(t, act)
	ctx = act.cfg.WithConfig(ctx)

	logBuf := &bytes.Buffer{}
	out.Stdout = logBuf
	stdout = logBuf
	defer func() {
		out.Stdout = os.Stdout
		stdout = os.Stdout
	}()

	dir := t.TempDir()
	baselineFile := dir + "/baseline.json"

	// a strong password crunchy accepts, used for the baseline.
	strongAlpha := "Zk9!mpR-29aqLx#42v"
	// a different strong password for a newly added secret.
	strongBeta := "Tr0ub4dor&3xK!77q"

	// Create the baseline report with a single, healthy secret.
	sec := secrets.NewAKV()
	sec.SetPassword(strongAlpha)
	require.NoError(t, act.Store.Set(ctx, "alpha", sec))
	require.NoError(t, act.Audit(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"format": "json", "output-file": baselineFile})))
	baselineBytes, err := os.ReadFile(baselineFile)
	require.NoError(t, err)
	require.NotEmpty(t, baselineBytes)
	logBuf.Reset()

	t.Run("--baseline without --format json is rejected", func(t *testing.T) {
		err := act.Audit(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"baseline": baselineFile}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--format json")
	})

	t.Run("missing baseline file is reported", func(t *testing.T) {
		err := act.Audit(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{
			"format":   "json",
			"baseline": dir + "/does-not-exist.json",
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load audit baseline report")
	})

	t.Run("invalid baseline prevents any output file write", func(t *testing.T) {
		invalid := dir + "/invalid.json"
		require.NoError(t, os.WriteFile(invalid, []byte("{not json"), 0o600))
		outFile := dir + "/should-not-exist.json"

		err := act.Audit(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{
			"format":      "json",
			"baseline":    invalid,
			"output-file": outFile,
		}))
		require.Error(t, err)
		_, statErr := os.Stat(outFile)
		assert.True(t, os.IsNotExist(statErr), "no partial report must be written")
	})

	t.Run("comparison report lists added secrets and new findings", func(t *testing.T) {
		// Weaken alpha and add a brand new secret.
		weak := secrets.NewAKV()
		weak.SetPassword("123")
		require.NoError(t, act.Store.Set(ctx, "alpha", weak))

		beta := secrets.NewAKV()
		beta.SetPassword(strongBeta)
		require.NoError(t, act.Store.Set(ctx, "beta", beta))

		outFile := dir + "/compared.json"
		require.NoError(t, act.Audit(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{
			"format":      "json",
			"baseline":    baselineFile,
			"output-file": outFile,
		})))

		data, err := os.ReadFile(outFile)
		require.NoError(t, err)

		var report struct {
			Sources  map[string]any `json:"secrets"`
			Baseline *struct {
				Path           string   `json:"path"`
				SecretsAdded   []string `json:"secrets_added"`
				SecretsRemoved []string `json:"secrets_removed"`
				Findings       []struct {
					Secret         string `json:"secret"`
					Analyzer       string `json:"analyzer"`
					Change         string `json:"change"`
					SeverityBefore string `json:"severity_before"`
					SeverityAfter  string `json:"severity_after"`
				} `json:"findings"`
			} `json:"baseline"`
		}
		require.NoError(t, json.Unmarshal(data, &report))

		// the full current results are preserved (foo is the default entry
		// created by the test harness).
		assert.Contains(t, report.Sources, "alpha")
		assert.Contains(t, report.Sources, "beta")
		assert.Contains(t, report.Sources, "foo")

		require.NotNil(t, report.Baseline)
		assert.Equal(t, baselineFile, report.Baseline.Path)
		assert.Equal(t, []string{"beta"}, report.Baseline.SecretsAdded)
		assert.Empty(t, report.Baseline.SecretsRemoved)

		var alphaCrunchy int
		for _, f := range report.Baseline.Findings {
			if f.Secret == "alpha" && f.Analyzer == "crunchy" {
				alphaCrunchy++
				assert.Equal(t, "new", f.Change)
				assert.Empty(t, f.SeverityBefore)
				assert.Equal(t, "warning", f.SeverityAfter)
			}
		}
		assert.Equal(t, 1, alphaCrunchy, "alpha/crunchy must be reported once as a new finding")

		// no plaintext passwords must leak into the report.
		assert.NotContains(t, string(data), strongAlpha)
		assert.NotContains(t, string(data), strongBeta)
	})

	t.Run("refusing to overwrite the baseline", func(t *testing.T) {
		err := act.Audit(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{
			"format":      "json",
			"baseline":    baselineFile,
			"output-file": baselineFile,
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to overwrite the baseline")

		after, err := os.ReadFile(baselineFile)
		require.NoError(t, err)
		assert.Equal(t, baselineBytes, after)
	})
}
