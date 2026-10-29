package action

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gopasspw/gopass/internal/action/exit"
	"github.com/gopasspw/gopass/internal/config"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/internal/store"
	"github.com/gopasspw/gopass/pkg/clipboard"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/gopasspw/gopass/pkg/gopass"
	"github.com/gopasspw/gopass/pkg/otp"
	"github.com/gopasspw/gopass/pkg/termio"
	"github.com/mattn/go-tty"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"github.com/urfave/cli/v3"
)

// OTP implements OTP token handling for TOTP and HOTP.
func (s *otpHandler) OTP(ctx context.Context, cmd *cli.Command) error {
	ctx = ctxutil.WithGlobalFlags(ctx, cmd)
	name := cmd.Args().First()
	if name == "" {
		return exit.Error(exit.Usage, nil, "Usage: %s otp <NAME>", s.Name)
	}

	qrf := cmd.String("qr")
	clip := config.Bool(ctx, "otp.onlyclip")
	if cmd.IsSet("clip") {
		clip = cmd.Bool("clip")
	}
	alsoClip := config.Bool(ctx, "otp.autoclip")
	if cmd.IsSet("alsoclip") {
		alsoClip = cmd.Bool("alsoclip")
	}
	chained := cmd.Bool("chained")
	pw := cmd.Bool("password")
	snip := cmd.Bool("snip")

	// --at computes a single TOTP token for a fixed point in time. It must be
	// validated before anything generates a token or mutates the store (e.g.
	// the --snip handling below or the HOTP counter update).
	at := time.Time{}
	if atValue := cmd.String("at"); atValue != "" {
		if snip {
			return exit.Error(exit.Usage, nil, "--at can not be combined with --snip")
		}
		if qrf != "" {
			return exit.Error(exit.Usage, nil, "--at can not be combined with --qr")
		}
		t, err := time.Parse(time.RFC3339, atValue)
		if err != nil {
			return exit.Error(exit.Usage, err, "Failed to parse %q as an RFC3339 timestamp: %s", atValue, err)
		}
		// normalize to the UTC instant so different zone offsets at the same
		// point in time yield the same token.
		at = t.UTC()
		debug.Log("computing OTP token for fixed point in time %s", at.Format(time.RFC3339))
	}

	if snip {
		qr, err := otp.ParseScreen(ctx)
		if err != nil || len(qr) == 0 {
			return err
		}

		choice, err := termio.AskForBool(ctx, "(Over)writing otpauth URL in key 'otpauth'?", true)
		if err != nil || !choice {
			return err
		}
		err = s.insertYAMLFn(ctxutil.WithInteractive(ctx, false), name, "otpauth", []byte(qr), nil)
		if err != nil {
			return err
		}

		out.Print(ctx, "Value written, carrying on to display OTP value from it.")
	}

	return s.otp(ctx, name, qrf, clip, pw, true, chained, alsoClip, at)
}

func tickingBar(ctx context.Context, expiresAt time.Time, bar *termio.ProgressBar) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for tt := range ticker.C {
		select {
		case <-ctx.Done():
			return // returning not to leak the goroutine.
		default:
			// we don't want to block if not cancelled.
		}
		if tt.After(expiresAt) {
			return
		}
		bar.Inc()
	}
}

func waitForKeyPress(ctx context.Context, cancel context.CancelFunc) (func(), func()) {
	tty1, err := tty.Open()
	if err != nil {
		out.Errorf(ctx, "Unexpected error opening tty: %v", err)
		cancel()
	}

	return func() {
			for {
				select {
				case <-ctx.Done():
					return // returning not to leak the goroutine.
				default:
				}

				r, err := tty1.ReadRune()
				if err != nil {
					out.Errorf(ctx, "Unexpected error opening tty: %v", err)
				}

				if r == 'q' || r == 'x' || err != nil {
					cancel()

					return
				}
			}
		}, func() {
			_ = tty1.Close()
		}
}

// nolint: cyclop
func (s *otpHandler) otp(ctx context.Context, name, qrf string, clip, pw, recurse, chained, alsoClip bool, at time.Time) error {
	sec, err := s.Store.Get(ctx, name)
	if err != nil {
		return s.otpHandleError(ctx, name, qrf, clip, pw, recurse, chained, alsoClip, at, err)
	}

	outerCtx := ctx
	ctx = config.WithMount(ctx, s.Store.MountPoint(name))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if !at.IsZero() {
		// Fixed point in time: TOTP only, single token, no refresh or countdown.
		return s.otpAt(ctx, name, sec, at, clip, chained, alsoClip)
	}

	skip := ctxutil.IsHidden(ctx) || pw || qrf != "" || !ctxutil.IsTerminal(ctx) || !ctxutil.IsInteractive(ctx) || clip
	if !skip {
		// let us monitor key presses for cancellation:.
		runFn, cleanupFn := waitForKeyPress(ctx, cancel)
		go runFn()
		defer cleanupFn()
	}

	// only used for the HOTP case as a fallback
	var counter uint64 = 1
	if sv, found := sec.Get("counter"); found && sv != "" {
		if iv, err := strconv.ParseUint(sv, 10, 64); iv != 0 && err == nil {
			counter = iv
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		two, err := otp.Calculate(name, sec)
		if err != nil {
			return exit.Error(exit.Unknown, err, "No OTP entry found for %s: %s", name, err)
		}

		var token string
		switch two.Type() {
		case "totp":
			token, err = totp.GenerateCodeCustom(two.Secret(), time.Now(), totp.ValidateOpts{
				Period:    uint(two.Period()),
				Skew:      1,
				Digits:    two.Digits(),
				Algorithm: two.Algorithm(),
				Encoder:   two.Encoder(),
			})
			if err != nil {
				return exit.Error(exit.Unknown, err, "Failed to compute OTP token for %s: %s", name, err)
			}
		case "hotp":
			token, err = hotp.GenerateCodeCustom(two.Secret(), counter, hotp.ValidateOpts{
				Digits:    two.Digits(),
				Algorithm: two.Algorithm(),
				Encoder:   two.Encoder(),
			})
			if err != nil {
				return exit.Error(exit.Unknown, err, "Failed to compute OTP token for %s: %s", name, err)
			}
			counter++
			_ = sec.Set("counter", strconv.Itoa(int(counter)))
			// using outerCtx here because we want to save the counter even if the user cancels.
			if err := s.Store.Set(outerCtx, name, sec); err != nil {
				out.Errorf(outerCtx, "Failed to persist counter value: %s", err)
			}
			debug.Log("Saved counter as %d", counter)
		}

		now := time.Now()
		expiresAt := now.Add(time.Duration(two.Period()) * time.Second).Truncate(time.Duration(two.Period()) * time.Second)
		secondsLeft := int(time.Until(expiresAt).Seconds())
		bar := termio.NewProgressBar(int64(secondsLeft))
		bar.Hidden = skip

		debug.Log("OTP period: %ds", two.Period())

		if chained {
			token = fmt.Sprintf("%s%s", sec.Password(), token)
		}
		if clip || alsoClip {
			if err := clipboard.CopyTo(ctx, fmt.Sprintf("token for %s", name), []byte(token), config.AsInt(s.cfg.Get("core.cliptimeout"))); err != nil {
				return exit.Error(exit.IO, err, "failed to copy to clipboard: %s", err)
			}
			if clip {
				return nil
			}
		}

		out.Printf(ctx, "%s", token)

		// In "QR-Code" mode just create the image file and then exit.
		if qrf != "" {
			return otp.WriteQRFile(two, qrf)
		}

		// If we are in "password mode", not interacting with a terminal or Stdout is attached to a pipe,
		// we are done.
		if skip {
			return nil
		}

		// if not then we want to print a progress bar with the expiry time.
		out.Warningf(ctx, "([q] to stop. -o flag to avoid.) This OTP password still lasts for:", nil)

		if bar.Hidden {
			cancel()
		} else {
			bar.Set(0)
			go tickingBar(ctx, expiresAt, bar)
		}

		// let us wait until next OTP code:.
		for {
			select {
			case <-ctx.Done():
				bar.Done()
				cancel()

				return nil
			default:
				time.Sleep(time.Millisecond * 500)
			}
			if time.Now().After(expiresAt) {
				bar.Done()

				break
			}
		}
	}
}

// otpAt computes exactly one TOTP token for the given point in time. It never
// refreshes, shows no countdown and never mutates the store (in particular it
// does not support HOTP entries, whose counter must not be touched). The
// token is written to the clipboard and/or printed once, using the same
// rules as the regular output path.
func (s *otpHandler) otpAt(ctx context.Context, name string, sec gopass.Secret, at time.Time, clip, chained, alsoClip bool) error {
	two, err := otp.Calculate(name, sec)
	if err != nil {
		return exit.Error(exit.Unknown, err, "No OTP entry found for %s: %s", name, err)
	}

	if two.Type() != "totp" {
		return exit.Error(exit.Usage, nil, "--at is only supported for TOTP entries, but %s is a %s entry", name, strings.ToUpper(two.Type()))
	}

	// at is already normalized to UTC. The TOTP counter derives from the
	// Unix time, so an exact period boundary rolls over to the next period.
	token, err := totp.GenerateCodeCustom(two.Secret(), at, totp.ValidateOpts{
		Period:    uint(two.Period()),
		Skew:      1,
		Digits:    two.Digits(),
		Algorithm: two.Algorithm(),
		Encoder:   two.Encoder(),
	})
	if err != nil {
		return exit.Error(exit.Unknown, err, "Failed to compute OTP token for %s: %s", name, err)
	}

	if chained {
		token = fmt.Sprintf("%s%s", sec.Password(), token)
	}

	if clip || alsoClip {
		if err := clipboard.CopyTo(ctx, fmt.Sprintf("token for %s", name), []byte(token), config.AsInt(s.cfg.Get("core.cliptimeout"))); err != nil {
			return exit.Error(exit.IO, err, "failed to copy to clipboard: %s", err)
		}
		if clip {
			return nil
		}
	}

	out.Printf(ctx, "%s", token)

	return nil
}

func (s *otpHandler) otpHandleError(ctx context.Context, name, qrf string, clip, pw, recurse, chained, alsoClip bool, at time.Time, err error) error {
	if !errors.Is(err, store.ErrNotFound) || !recurse || !ctxutil.IsTerminal(ctx) {
		return exit.Error(exit.Unknown, err, "failed to retrieve secret %q: %s", name, err)
	}

	out.Printf(ctx, "Entry %q not found. Starting search...", name)
	cb := func(ctx context.Context, cmd *cli.Command, name string, recurse bool) error {
		return s.otp(ctx, name, qrf, clip, pw, false, chained, alsoClip, at)
	}
	if err := s.findFn(ctx, nil, name, cb, false); err != nil {
		return exit.Error(exit.NotFound, err, "%s", err)
	}

	return nil
}
