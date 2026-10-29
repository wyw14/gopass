package action

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/gopasspw/gopass/internal/backend"
	"github.com/gopasspw/gopass/internal/config"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/tests/gptest"
	"github.com/stretchr/testify/require"
)

func TestHistory(t *testing.T) {
	u := gptest.NewUnitTester(t)

	for _, k := range []string{"DEBFULLNAME", "DEBEMAIL", "USER", "EMAIL"} {
		t.Setenv(k, "")
	}
	t.Setenv("GIT_AUTHOR_NAME", "foo bar")
	t.Setenv("GIT_AUTHOR_EMAIL", "foo.bar@example.org")

	ctx := config.NewContextInMemory()
	ctx = ctxutil.WithAlwaysYes(ctx, true)
	ctx = ctxutil.WithInteractive(ctx, false)

	ctx = backend.WithCryptoBackend(ctx, backend.Plain)
	ctx = backend.WithStorageBackend(ctx, backend.GitFS)

	cfg := config.NewInMemory()
	require.NoError(t, cfg.SetPath(u.StoreDir("")))

	act, err := newAction(cfg, semver.Version{}, false)
	require.NoError(t, err)
	require.NotNil(t, act)
	ctx = act.cfg.WithConfig(ctx)

	t.Run("can initialize", func(t *testing.T) {
		_, errIsInit := act.IsInitialized(ctx, gptest.CliCtx(ctx, t))

		require.NoError(t, errIsInit)
	})

	buf := &bytes.Buffer{}
	out.Stdout = buf
	defer func() {
		out.Stdout = os.Stdout
	}()

	t.Run("init git", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.rcsInit(ctx, "", "foo bar", "foo.bar@example.org"))
		t.Logf("init git: %s", buf.String())
	})

	t.Run("insert bar", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.Insert(ctx, gptest.CliCtx(ctx, t, "bar")))
	})

	t.Run("update bar a second time", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.insertStdin(ctx, "bar", []byte("pw2"), false))
	})

	t.Run("update bar a third time", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.insertStdin(ctx, "bar", []byte("pw3"), false))
	})

	t.Run("history bar", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.History(ctx, gptest.CliCtx(ctx, t, "bar")))
		// one "Save secret" subject per printed revision
		require.Equal(t, 3, strings.Count(buf.String(), "Save secret"))
	})

	t.Run("history --password bar", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.History(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"password": "true"}, "bar")))
		require.Equal(t, 3, strings.Count(buf.String(), "Save secret"))
	})

	t.Run("history --limit=1 bar", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.History(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"limit": "1"}, "bar")))
		require.Equal(t, 1, strings.Count(buf.String(), "Save secret"))
	})

	t.Run("history --limit=2 --password bar", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.History(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"limit": "2", "password": "true"}, "bar")))
		require.Equal(t, 2, strings.Count(buf.String(), "Save secret"))
		// the limited revisions carry the newest passwords pw3 and pw2, not pw
		require.Contains(t, buf.String(), " - pw3")
		require.Contains(t, buf.String(), " - pw2")
		require.NotContains(t, buf.String(), " - pw1")
	})

	t.Run("history --limit=10 bar shows all revisions", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.History(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"limit": "10"}, "bar")))
		require.Equal(t, 3, strings.Count(buf.String(), "Save secret"))
	})

	t.Run("history --limit=0 bar fails", func(t *testing.T) {
		defer buf.Reset()
		require.ErrorContains(t, act.History(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"limit": "0"}, "bar")), "positive integer")
	})

	t.Run("history --limit=-1 bar fails", func(t *testing.T) {
		defer buf.Reset()
		require.ErrorContains(t, act.History(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"limit": "-1"}, "bar")), "positive integer")
	})
}
