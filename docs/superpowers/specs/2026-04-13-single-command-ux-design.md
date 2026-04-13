# Single-Command UX

Simplify the benchmark suite so contributors run one command (`./bench`) and get clear instructions on how to submit.

## Problem

The current workflow requires users to know about `setup`, `run-all`, and `submit` as separate steps. Too many subcommands are documented in the README, making the project look more complex than it is.

## Design

### Default command: bare `./bench`

When invoked with no subcommand, `./bench` runs the full pipeline:

1. **Setup** -- validate prereqs (Python, hashcat binary, gh CLI, dependencies)
2. **Run all** -- correctness tests, synthetic benchmarks (30 trials), real-world benchmarks (if rockyou.txt is found)
3. **Print submission instructions** -- tell the user to run `./bench submit`

If any step fails, execution stops and the error is reported.

The submission banner printed at the end:

```
══════════════════════════════════════════════════
  Benchmarks complete! Results saved to results/

  To submit your findings:
    ./bench submit

  This will review your results for PII, then
  create a GitHub PR on your behalf.
══════════════════════════════════════════════════
```

### Documented subcommands (README)

Only two subcommands appear in the README:

- `./bench submit` -- review results for PII, create GitHub PR
- `./bench clean` -- remove generated files and build artifacts

### Undocumented subcommands (--help only)

All existing subcommands continue to work. They are discoverable via `./bench --help` and `./bench <command> --help` but not mentioned in the README.

The argparse help text for each subcommand must be self-documenting -- clear enough that `--help` is sufficient without external docs. Audit and improve descriptions for:

- `setup` -- what it checks
- `detect` -- what it outputs
- `test` -- what test suite runs
- `generate-corpus` -- what tiers are generated
- `run-correctness` -- what build matrix is tested
- `run-synthetic` -- trials, modes, vec widths
- `run-real-world` -- requires rockyou.txt, what it measures
- `run-all` -- what it includes
- `quick-synthetic` / `quick-real-world` -- 3 trials, for iteration not submission

### README rewrite

Structure:

1. **Title and one-line description**
2. **Quick Start** -- clone, cd, `./bench` (three lines)
3. **Runtime note** -- ~20-45 minutes depending on GPU
4. **Requirements** -- uv, hashcat binary, gh CLI, optional rockyou.txt
5. **Submitting Results** -- `./bench submit`
6. **Configuration** -- flags and env vars table (hashcat-src, rockyou-path, trials, results-dir)
7. **Cleanup** -- `./bench clean`

No subcommand table. No advanced section.

## Changes required

### `bench` script

- Make `command` subparser not required (`required=False`)
- Set default command to `None`; when `None`, run `cmd_default(args)`
- `cmd_default` calls `cmd_setup`, then `cmd_run_all`, then prints the submission banner
- Improve argparse help strings for all subcommands to be self-documenting

### `README.md`

- Rewrite per the structure above

## Out of scope

- No changes to benchmark logic, correctness tests, submission flow, or validation
- No changes to tool scripts in `tools/`
- No new dependencies
