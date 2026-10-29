# `history` command

The `gopass history` command will show all revisions of a given secret.

## Synopsis

```
$ gopass history entry
$ gopass history --limit 5 entry
```

## Modes of operation

* Display all revisions of the given secret.
* With `--limit` only display the first N revisions in the order they are returned (newest first). When combined with `--password` only those N revisions are decrypted and their passwords shown.

## Flags

Flag | Aliases | Description
---- | ------- | -----------
`--password` | `-p` | Include the password of each displayed revision in the output.
`--limit` | `-l` | Display no more than this many revisions. Must be a positive integer. When omitted all revisions are displayed.
