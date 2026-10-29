package action

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopasspw/gopass/internal/config"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/tests/gptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMounts(t *testing.T) {
	u := gptest.NewUnitTester(t)

	ctx := config.NewContextInMemory()
	ctx = ctxutil.WithAlwaysYes(ctx, true)
	ctx = ctxutil.WithTerminal(ctx, false)
	act, err := newMock(ctx, u.StoreDir(""))
	require.NoError(t, err)
	require.NotNil(t, act)
	ctx = act.cfg.WithConfig(ctx)

	buf := &bytes.Buffer{}
	out.Stdout = buf
	out.Stderr = buf
	stdout = buf
	defer func() {
		out.Stdout = os.Stdout
		out.Stderr = os.Stderr
		stdout = os.Stdout
	}()

	t.Run("print mounts", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.MountsPrint(ctx, gptest.CliCtx(ctx, t)))
	})

	t.Run("print mounts as JSON without mounts returns empty array", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.MountsPrint(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"json": "true"})))

		var mounts []struct {
			Alias string `json:"alias"`
			Path  string `json:"path"`
		}
		require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &mounts))
		assert.Empty(t, mounts)
		// the raw output must be an empty JSON array, not null
		assert.Equal(t, "[]", string(bytes.TrimSpace(buf.Bytes())))
	})

	t.Run("complete mounts", func(t *testing.T) {
		defer buf.Reset()
		act.MountsComplete(ctx, gptest.CliCtx(ctx, t))
		assert.Empty(t, buf.String())
	})

	t.Run("remove no non-existing mount", func(t *testing.T) {
		defer buf.Reset()
		require.Error(t, act.MountRemove(ctx, gptest.CliCtx(ctx, t)))
	})

	t.Run("remove non-existing mount", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.MountRemove(ctx, gptest.CliCtx(ctx, t, "foo")))
	})

	t.Run("add non-existing mount", func(t *testing.T) {
		defer buf.Reset()
		require.Error(t, act.MountAdd(ctx, gptest.CliCtx(ctx, t, "foo", filepath.Join(u.Dir, "mount1"))))
	})

	t.Run("add some mounts", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, u.InitStore("mount1"))
		require.NoError(t, u.InitStore("mount2"))
		require.NoError(t, act.Store.AddMount(ctx, "mount1", u.StoreDir("mount1")))
		require.NoError(t, act.Store.AddMount(ctx, "mount2", u.StoreDir("mount2")))
	})

	t.Run("print mounts", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.MountsPrint(ctx, gptest.CliCtx(ctx, t)))
	})

	t.Run("print mounts as JSON", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.MountsPrint(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"json": "true"})))

		var mounts []struct {
			Alias string `json:"alias"`
			Path  string `json:"path"`
		}
		require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &mounts))
		require.Len(t, mounts, 2)
		// aliases are sorted for deterministic output
		assert.Equal(t, "mount1", mounts[0].Alias)
		assert.Equal(t, "mount2", mounts[1].Alias)
		assert.Equal(t, act.Store.Mounts()["mount1"], mounts[0].Path)
		assert.Equal(t, act.Store.Mounts()["mount2"], mounts[1].Path)
	})

	t.Run("add mount with spaces and special characters in path", func(t *testing.T) {
		defer buf.Reset()
		weirdDir := filepath.Join(u.Dir, "weird dir & spécial (1)")
		require.NoError(t, os.MkdirAll(weirdDir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(weirdDir, ".plain-id"), []byte("0xDEADBEEF\n"), 0o600))
		require.NoError(t, act.Store.AddMount(ctx, "weird", weirdDir))
	})

	t.Run("print mounts as JSON preserves paths verbatim", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.MountsPrint(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"json": "true"})))

		var mounts []struct {
			Alias string `json:"alias"`
			Path  string `json:"path"`
		}
		require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &mounts))
		require.Len(t, mounts, 3)

		got := make(map[string]string, len(mounts))
		for _, m := range mounts {
			got[m.Alias] = m.Path
		}
		// the decoded path must be byte-identical to the actual mount path
		assert.Equal(t, act.Store.Mounts()["weird"], got["weird"])
		assert.Contains(t, got["weird"], "weird dir & spécial (1)")
		// spaces are emitted verbatim in the raw JSON; '&' is standard JSON
		// escaped (\u0026) but decodes back to the original character
		assert.Contains(t, buf.String(), "weird dir ")
	})

	t.Run("text tree output still works with special paths", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.MountsPrint(ctx, gptest.CliCtx(ctx, t)))
		assert.Contains(t, buf.String(), "gopass (")
		assert.Contains(t, buf.String(), "weird")
	})
}
