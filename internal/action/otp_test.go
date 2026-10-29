package action

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gokyle/twofactor"
	"github.com/gopasspw/gopass/internal/config"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/gopass/secrets"
	"github.com/gopasspw/gopass/tests/gptest"
	potp "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOTP(t *testing.T) {
	u := gptest.NewUnitTester(t)

	ctx := config.NewContextInMemory()
	ctx = ctxutil.WithAlwaysYes(ctx, true)
	ctx = ctxutil.WithInteractive(ctx, false)

	act, err := newMock(ctx, u.StoreDir(""))
	require.NoError(t, err)
	require.NotNil(t, act)
	ctx = act.cfg.WithConfig(ctx)

	buf := &bytes.Buffer{}
	out.Stdout = buf
	defer func() {
		out.Stdout = os.Stdout
	}()

	t.Run("display non-otp secret", func(t *testing.T) {
		defer buf.Reset()
		require.Error(t, act.OTP(ctx, gptest.CliCtx(ctx, t, "foo")))
	})

	t.Run("create and display valid OTP", func(t *testing.T) {
		defer buf.Reset()
		sec := secrets.NewAKV()
		sec.SetPassword("foo")
		_, err := sec.Write([]byte(twofactor.GenerateGoogleTOTP().URL("foo") + "\n"))
		require.NoError(t, err)
		require.NoError(t, act.Store.Set(ctx, "bar", sec))

		require.NoError(t, act.OTP(ctx, gptest.CliCtx(ctx, t, "bar")))

		// add some unrelated body material, it should still work
		_, err = sec.Write([]byte("more body content, unrelated to otp"))
		require.NoError(t, err)
		require.NoError(t, act.Store.Set(ctx, "bar", sec))

		require.NoError(t, act.OTP(ctx, gptest.CliCtx(ctx, t, "bar")))
	})

	t.Run("copy to clipboard", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.otp(ctx, "bar", "", true, false, false, false, false, time.Time{}))
	})

	t.Run("copy to clipboard chained", func(t *testing.T) {
		defer buf.Reset()
		require.NoError(t, act.otp(ctx, "bar", "", true, false, false, true, false, time.Time{}))
	})

	t.Run("write QR file", func(t *testing.T) {
		defer buf.Reset()
		fn := filepath.Join(u.Dir, "qr.png")
		require.NoError(t, act.OTP(ctx, gptest.CliCtxWithFlags(ctx, t, map[string]string{"qr": fn}, "bar")))
		assert.FileExists(t, fn)
	})
}

func TestOTPAt(t *testing.T) {
	u := gptest.NewUnitTester(t)

	ctx := config.NewContextInMemory()
	ctx = ctxutil.WithAlwaysYes(ctx, true)
	ctx = ctxutil.WithInteractive(ctx, false)

	act, err := newMock(ctx, u.StoreDir(""))
	require.NoError(t, err)
	require.NotNil(t, act)
	ctx = act.cfg.WithConfig(ctx)

	buf := &bytes.Buffer{}
	out.Stdout = buf
	defer func() {
		out.Stdout = os.Stdout
	}()

	const otpSecret = "JBSWY3DPEHPK3PXP"

	// standard TOTP entry: 30s period, 6 digits, SHA1, password "chainedpw".
	totpSec := secrets.NewAKV()
	totpSec.SetPassword("chainedpw")
	_, err = totpSec.Write([]byte("otpauth://totp/Example:alice?secret=" + otpSecret + "&issuer=Example&period=30&digits=6&algorithm=SHA1\n"))
	require.NoError(t, err)
	require.NoError(t, act.Store.Set(ctx, "fixed", totpSec))

	// custom TOTP entry exercising the entry's own period/digits/algorithm.
	customSec := secrets.NewAKV()
	customSec.SetPassword("foo")
	_, err = customSec.Write([]byte("otpauth://totp/Example:carol?secret=" + otpSecret + "&issuer=Example&period=60&digits=8&algorithm=SHA256\n"))
	require.NoError(t, err)
	require.NoError(t, act.Store.Set(ctx, "custom", customSec))

	// HOTP entry with a counter that --at must never touch.
	hotpEntry := secrets.NewAKV()
	hotpEntry.SetPassword("hfoo")
	require.NoError(t, hotpEntry.Set("counter", "5"))
	_, err = hotpEntry.Write([]byte("otpauth://hotp/Example:bob?secret=" + otpSecret + "&issuer=Example&counter=5\n"))
	require.NoError(t, err)
	require.NoError(t, act.Store.Set(ctx, "hotpentry", hotpEntry))

	wantTOTP := func(t *testing.T, at string, period uint, digits potp.Digits, algo potp.Algorithm) string {
		t.Helper()
		ts, perr := time.Parse(time.RFC3339, at)
		require.NoError(t, perr)
		code, gerr := totp.GenerateCodeCustom(otpSecret, ts.UTC(), totp.ValidateOpts{
			Period:    period,
			Skew:      1,
			Digits:    digits,
			Algorithm: algo,
		})
		require.NoError(t, gerr)

		return code
	}

	// runAt invokes `gopass otp --at=<at> [flags] entry` and returns the
	// trimmed single-line output plus the error.
	runAt := func(t *testing.T, entry, at string, flags map[string]string) (string, error) {
		t.Helper()
		cmdFlags := map[string]string{"at": at}
		for k, v := range flags {
			cmdFlags[k] = v
		}
		gerr := act.OTP(ctx, gptest.CliCtxWithFlags(ctx, t, cmdFlags, entry))
		output := strings.TrimSpace(buf.String())
		buf.Reset()

		return output, gerr
	}

	const validAt = "2033-05-07T08:29:00Z"
	want := wantTOTP(t, validAt, 30, potp.DigitsSix, potp.AlgorithmSHA1)

	t.Run("fixed UTC time, single token, no secret leakage", func(t *testing.T) {
		got, gerr := runAt(t, "fixed", validAt, nil)
		require.NoError(t, gerr)
		assert.Equal(t, want, got)
		assert.Len(t, got, 6)
		assert.NotContains(t, got, otpSecret)
		assert.NotContains(t, got, "otpauth://")
	})

	t.Run("deterministic across repeated calls", func(t *testing.T) {
		first, err := runAt(t, "fixed", validAt, nil)
		require.NoError(t, err)
		second, err := runAt(t, "fixed", validAt, nil)
		require.NoError(t, err)
		assert.Equal(t, want, first)
		assert.Equal(t, want, second)
	})

	t.Run("same instant in different timezones", func(t *testing.T) {
		zones := []string{
			"2033-05-07T08:30:00Z",
			"2033-05-07T10:30:00+02:00",
			"2033-05-07T03:30:00-05:00",
			"2033-05-07T18:30:00+10:00",
		}
		expected := wantTOTP(t, zones[0], 30, potp.DigitsSix, potp.AlgorithmSHA1)
		for _, z := range zones {
			got, gerr := runAt(t, "fixed", z, nil)
			require.NoError(t, gerr, z)
			assert.Equal(t, expected, got, z)
		}
	})

	t.Run("rolls over at the exact period boundary", func(t *testing.T) {
		before, err := runAt(t, "fixed", "2033-05-07T08:29:59Z", nil)
		require.NoError(t, err)
		boundary, err := runAt(t, "fixed", "2033-05-07T08:30:00Z", nil)
		require.NoError(t, err)
		after, err := runAt(t, "fixed", "2033-05-07T08:30:29Z", nil)
		require.NoError(t, err)
		assert.NotEqual(t, before, boundary)
		assert.Equal(t, boundary, after)
		assert.Equal(t, wantTOTP(t, "2033-05-07T08:30:00Z", 30, potp.DigitsSix, potp.AlgorithmSHA1), boundary)
	})

	t.Run("uses the entry's period, digits and algorithm", func(t *testing.T) {
		got, gerr := runAt(t, "custom", validAt, nil)
		require.NoError(t, gerr)
		assert.Len(t, got, 8)
		assert.Equal(t, wantTOTP(t, validAt, 60, potp.DigitsEight, potp.AlgorithmSHA256), got)

		// 60s boundary is at the minute.
		before, err := runAt(t, "custom", "2033-05-07T08:29:59Z", nil)
		require.NoError(t, err)
		boundary, err := runAt(t, "custom", "2033-05-07T08:30:00Z", nil)
		require.NoError(t, err)
		assert.NotEqual(t, before, boundary)
		assert.Equal(t, wantTOTP(t, "2033-05-07T08:30:00Z", 60, potp.DigitsEight, potp.AlgorithmSHA256), boundary)
	})

	t.Run("rejects invalid or timezone-less timestamps", func(t *testing.T) {
		for _, bad := range []string{
			"not-a-time",
			"2033-05-07T08:30:00", // RFC3339 without a zone offset
			"2033-13-40T99:99:99Z",
			"2033-05-07",
		} {
			got, gerr := runAt(t, "fixed", bad, nil)
			require.Error(t, gerr, bad)
			require.ErrorContains(t, gerr, "RFC3339", bad)
			assert.Empty(t, got, bad)
		}
	})

	t.Run("can not be combined with --qr", func(t *testing.T) {
		fn := filepath.Join(u.Dir, "at-qr.png")
		got, gerr := runAt(t, "fixed", validAt, map[string]string{"qr": fn})
		require.Error(t, gerr)
		require.ErrorContains(t, gerr, "--at")
		assert.Empty(t, got)
		assert.NoFileExists(t, fn)
	})

	t.Run("can not be combined with --snip", func(t *testing.T) {
		got, gerr := runAt(t, "fixed", validAt, map[string]string{"snip": "true"})
		require.Error(t, gerr)
		require.ErrorContains(t, gerr, "--at")
		assert.Empty(t, got)
	})

	t.Run("rejects HOTP entries without touching the counter", func(t *testing.T) {
		got, gerr := runAt(t, "hotpentry", validAt, nil)
		require.Error(t, gerr)
		require.ErrorContains(t, gerr, "TOTP")
		assert.Empty(t, got)

		sec, gerr := act.Store.Get(ctx, "hotpentry")
		require.NoError(t, gerr)
		counter, found := sec.Get("counter")
		require.True(t, found)
		assert.Equal(t, "5", counter)
	})

	t.Run("chained prepends the password", func(t *testing.T) {
		got, gerr := runAt(t, "fixed", validAt, map[string]string{"chained": "true"})
		require.NoError(t, gerr)
		assert.Equal(t, "chainedpw"+want, got)
	})

	t.Run("password mode prints the single token", func(t *testing.T) {
		got, gerr := runAt(t, "fixed", validAt, map[string]string{"password": "true"})
		require.NoError(t, gerr)
		assert.Equal(t, want, got)
	})

	t.Run("--clip copies instead of printing, --alsoclip does both", func(t *testing.T) {
		at := time.Date(2033, 5, 7, 8, 29, 0, 0, time.UTC)
		require.NoError(t, act.otp(ctx, "fixed", "", true, false, false, false, false, at))
		assert.Empty(t, strings.TrimSpace(buf.String()))
		buf.Reset()

		require.NoError(t, act.otp(ctx, "fixed", "", false, false, false, false, true, at))
		assert.Equal(t, want, strings.TrimSpace(buf.String()))
		buf.Reset()
	})
}
