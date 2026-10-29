# `audit` command

The `audit` command will decrypt all secrets and scan for weak passwords or other common flaws.

## Synopsis

```bash
gopass audit
```

## Excludes

You can exclude certain secrets from the audit by adding a `.gopass-audit-exclude` file to the secret. The file should contain a list of RE2 patters to exclude, one per line. For example:

```bash
# Lines starting with # are ignored. Trailing comments are not supported.
# Exclude all secrets in the pin folder.
# Note: These are RE2, not Glob patterns!
pin/.*
# Literal matches are also valid RE2 patterns
test_folder/ignore_this
# Gopass internally uses forward slashes as path separators, even on Windows. So no need to escape backslashes.
```

## JSON baseline comparison

When writing a JSON report with `--format json` you can pass `--baseline` with the path of a JSON report from a previous audit run. The new report keeps the full current results and gains an additional `baseline` section describing the differences between the two runs:

```bash
gopass audit --format json --output-file report.json
gopass audit --format json --baseline report.json --output-file report-new.json
```

Findings are matched by secret name and analyzer name:

- `new`: a finding that was not present in the baseline (a severity of `none` is not considered a finding).
- `resolved`: a finding from the baseline that is gone in the current report.
- `severity_changed`: the severity of a finding changed. A message-only change is not reported.

Findings are only compared for secrets present in both reports. Secrets that only exist in the current report are listed under `secrets_added`, secrets that only exist in the baseline under `secrets_removed`, so out-of-scope secrets are never mistaken for fixed issues. All lists are sorted stably by secret name and analyzer name.

The flag is only accepted together with `--format json`. A missing baseline file, invalid JSON or findings missing required fields abort the run with an error, and gopass never overwrites the baseline file itself.

## Exit codes

| Code | Meaning |
| -----: | --------- |
| 0 | No issues found |
| 1 | Audit run itself failed |
| 13 | Store contents could not be listed |
| 14 | One or more weak passwords or issues detected |
| 18 | Report file could not be written |

See [docs/exit-codes.md](../exit-codes.md) for the full table.

## Password strength backends

| Backend                                         | Description                                                            |
|-------------------------------------------------|------------------------------------------------------------------------|
| [`crunchy`](https://github.com/muesli/crunchy)  | Crunchy password strength checker                                      |
| `name`                                          | Checks if password equals the name of the secret                       |
