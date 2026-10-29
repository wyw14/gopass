package action

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/gopasspw/gopass/internal/backend"
	"github.com/gopasspw/gopass/internal/config"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/tests/gptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRevertTestAction creates an initialized test action backed by the plain
// crypto backend and a GitFS storage, i.e. revisions are real Git commits.
func newRevertTestAction(t *testing.T) (context.Context, *Action, *bytes.Buffer) {
	t.Helper()

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

	_, err = act.IsInitialized(ctx, gptest.CliCtx(ctx, t))
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	out.Stdout = buf
	t.Cleanup(func() {
		out.Stdout = os.Stdout
	})

	require.NoError(t, act.rcsInit(ctx, "", "foo bar", "foo.bar@example.org"))
	buf.Reset()

	return ctx, act, buf
}

func TestRevert(t *testing.T) {
	ctx, act, buf := newRevertTestAction(t)

	name := "revert/target"

	// create two revisions: oldpass (oldest) and newpass (current)
	require.NoError(t, act.insertStdin(ctx, name, []byte("oldpass"), false))
	require.NoError(t, act.insertStdin(ctx, name, []byte("newpass"), false))
	buf.Reset()

	revs, err := act.Store.ListRevisions(ctx, name)
	require.NoError(t, err)
	require.Len(t, revs, 2)

	// git log lists newest first, so the oldest revision is the last entry
	oldRev := revs[len(revs)-1].Hash
	newRev := revs[0].Hash
	require.NotEqual(t, oldRev, newRev)

	cur, err := act.Store.Get(ctx, name)
	require.NoError(t, err)
	require.Equal(t, "newpass", cur.Password())

	t.Run("usage errors", func(t *testing.T) {
		defer buf.Reset()

		require.Error(t, act.Revert(ctx, gptest.CliCtx(ctx, t)))
		require.Error(t, act.Revert(ctx, gptest.CliCtx(ctx, t, name)))
		require.Error(t, act.Revert(ctx, gptest.CliCtx(ctx, t, name, oldRev, "extra")))

		// nothing must have changed
		cur, err := act.Store.Get(ctx, name)
		require.NoError(t, err)
		assert.Equal(t, "newpass", cur.Password())
	})

	t.Run("missing secret", func(t *testing.T) {
		defer buf.Reset()

		require.Error(t, act.Revert(ctx, gptest.CliCtx(ctx, t, "revert/does-not-exist", oldRev)))

		// the current value must be untouched
		cur, err := act.Store.Get(ctx, name)
		require.NoError(t, err)
		assert.Equal(t, "newpass", cur.Password())
	})

	t.Run("missing revision", func(t *testing.T) {
		defer buf.Reset()

		require.Error(t, act.Revert(ctx, gptest.CliCtx(ctx, t, name, "0123456789abcdef0123456789abcdef01234567")))

		// the current value must be untouched
		cur, err := act.Store.Get(ctx, name)
		require.NoError(t, err)
		assert.Equal(t, "newpass", cur.Password())
	})

	t.Run("aborted without confirmation", func(t *testing.T) {
		defer buf.Reset()

		noCtx := ctxutil.WithAlwaysYes(ctx, false)
		noCtx = ctxutil.WithInteractive(noCtx, false)

		err := act.Revert(noCtx, gptest.CliCtx(noCtx, t, name, oldRev))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "aborted")

		// the current value must be untouched
		cur, err := act.Store.Get(noCtx, name)
		require.NoError(t, err)
		assert.Equal(t, "newpass", cur.Password())
	})

	t.Run("revert with --yes", func(t *testing.T) {
		defer buf.Reset()

		yesCtx := ctxutil.WithAlwaysYes(ctx, false)
		yesCtx = ctxutil.WithInteractive(yesCtx, false)

		// the target secret and revision are displayed before writing
		c := gptest.CliCtxWithFlags(yesCtx, t, map[string]string{"yes": "true"}, name, oldRev)
		require.NoError(t, act.Revert(yesCtx, c))
		assert.Contains(t, buf.String(), "Name:     "+name)
		assert.Contains(t, buf.String(), oldRev)

		// the secret now contains the historical plaintext, re-encrypted
		// through the regular write path
		cur, err := act.Store.Get(yesCtx, name)
		require.NoError(t, err)
		assert.Equal(t, "oldpass", cur.Password())

		// history is preserved: a new revision was added on top of the
		// existing ones, no commit was removed or reset.
		revs2, err := act.Store.ListRevisions(yesCtx, name)
		require.NoError(t, err)
		assert.Len(t, revs2, len(revs)+1)

		hashes := map[string]bool{}
		for _, r := range revs2 {
			hashes[r.Hash] = true
		}

		assert.True(t, hashes[oldRev], "old revision %s must be kept", oldRev)
		assert.True(t, hashes[newRev], "intermediate revision %s must be kept", newRev)
		assert.Contains(t, revs2[0].Subject, oldRev)
		assert.Contains(t, revs2[0].Subject, "Revert")
	})

	t.Run("revert again to identical content is a no-op", func(t *testing.T) {
		defer buf.Reset()

		// the previous subtest already restored oldRev, so writing the same
		// decrypted content again results in ErrMeaninglessWrite; this must
		// be reported as success and must not create another revision
		before, err := act.Store.ListRevisions(ctx, name)
		require.NoError(t, err)

		require.NoError(t, act.Revert(ctx, gptest.CliCtx(ctx, t, name, oldRev)))

		after, err := act.Store.ListRevisions(ctx, name)
		require.NoError(t, err)
		assert.Len(t, after, len(before))
	})
}

func TestRevertOffset(t *testing.T) {
	ctx, act, buf := newRevertTestAction(t)

	name := "revert/offset"

	require.NoError(t, act.insertStdin(ctx, name, []byte("v1"), false))
	require.NoError(t, act.insertStdin(ctx, name, []byte("v2"), false))
	require.NoError(t, act.insertStdin(ctx, name, []byte("v3"), false))
	buf.Reset()

	cur, err := act.Store.Get(ctx, name)
	require.NoError(t, err)
	require.Equal(t, "v3", cur.Password())

	// -1 selects the oldest revision
	require.NoError(t, act.Revert(ctx, gptest.CliCtx(ctx, t, name, "-1")))

	cur, err = act.Store.Get(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, "v1", cur.Password())
}
