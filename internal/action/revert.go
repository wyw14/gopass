package action

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gopasspw/gopass/internal/action/exit"
	"github.com/gopasspw/gopass/internal/backend"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/internal/store"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/debug"
	"github.com/gopasspw/gopass/pkg/termio"
	"github.com/urfave/cli/v3"
)

// Revert restores the content of a past revision as the current version of
// a secret. The historical ciphertext is read and decrypted first and then
// written back through the regular write path, which re-encrypts it to the
// currently usable recipients. The result is stored as a new revision, so the
// existing Git history (including later commits) is preserved and no branch
// reset is performed.
func (s *secretHandler) Revert(ctx context.Context, cmd *cli.Command) error {
	ctx = ctxutil.WithGlobalFlags(ctx, cmd)

	name := cmd.Args().Get(0)
	revision := cmd.Args().Get(1)

	if name == "" || revision == "" || cmd.Args().Len() > 2 {
		return exit.Error(exit.Usage, nil, "Usage: %s revert <NAME> <REVISION>", s.Name)
	}

	if !s.Store.Exists(ctx, name) {
		return exit.Error(exit.NotFound, nil, "Secret %q does not exist", name)
	}

	// Resolve "-N" style offsets to an exact revision.
	revision, err := s.parseRevision(ctx, name, revision)
	if err != nil {
		return exit.Error(exit.Unknown, err, "Failed to resolve revision for %q: %s", name, err)
	}

	// Revision metadata is informational only. Backends without RCS support
	// may fail to list revisions even though a named revision (e.g. "HEAD")
	// can still be read.
	var rev backend.Revision

	revFound := false

	if revs, errList := s.Store.ListRevisions(ctx, name); errList == nil {
		for _, r := range revs {
			if r.Hash == revision {
				rev = r
				revFound = true

				break
			}
		}
	} else {
		debug.Log("Failed to list revisions for %q: %s", name, errList)
	}

	// Read and decrypt the historical content BEFORE asking for confirmation
	// or writing anything. A missing revision or a decryption failure must
	// leave the current value of the secret untouched.
	ctx, sec, err := s.Store.GetRevision(ctx, name, revision)
	if err != nil {
		if errors.Is(err, store.ErrDecrypt) {
			return exit.Error(exit.Decrypt, err, "Failed to decrypt revision %q of secret %q", revision, name)
		}

		if !revFound {
			return exit.Error(exit.NotFound, err, "Revision %q of secret %q not found", revision, name)
		}

		return exit.Error(exit.Unknown, err, "Failed to read revision %q of secret %q: %s", revision, name, err)
	}

	// Show the target secret and the selected revision before writing.
	out.Printf(ctx, "Name:     %s", name)

	if revFound {
		out.Printf(ctx, "Revision: %s - %s <%s> - %s - %s", rev.Hash, rev.AuthorName, rev.AuthorEmail, rev.Date.Format(time.RFC3339), rev.Subject)
	} else {
		out.Printf(ctx, "Revision: %s", revision)
	}

	if !termio.AskForConfirmation(ctx, fmt.Sprintf("Do you want to revert %q to the content of this revision? It will be written as a new revision.", name)) {
		return exit.Error(exit.Aborted, nil, "revert aborted")
	}

	// Write the decrypted historical content through the regular write path:
	// this re-encrypts it for the currently usable recipients and creates a
	// new commit instead of restoring the old ciphertext or resetting any
	// branches.
	ctx = ctxutil.WithCommitMessage(ctx, fmt.Sprintf("Revert secret to revision %s", revision))

	if err := s.Store.Set(ctx, name, sec); err != nil {
		if errors.Is(err, store.ErrMeaninglessWrite) {
			out.Warningf(ctx, "The content of revision %q equals the current value. Nothing to do.", revision)

			return nil
		}

		return exit.Error(exit.Encrypt, err, "Failed to revert %q: %s", name, err)
	}

	out.Printf(ctx, "Reverted %q to revision %s", name, revision)

	return nil
}
