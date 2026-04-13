# Single-Command UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make bare `./bench` run the full pipeline (setup + benchmarks) and print submission instructions, then simplify the README to match.

**Architecture:** Add a default command handler to the existing argparse CLI. Improve help text for all subcommands so `--help` is self-documenting. Rewrite README to show only the essential workflow.

**Tech Stack:** Python 3.12+, argparse

---

### Task 1: Add default command to `bench` script

**Files:**
- Modify: `bench:228-249` (argparse setup)
- Modify: `bench:252-265` (COMMANDS dict)
- Modify: `bench:268-275` (main function)

- [ ] **Step 1: Make subcommand optional and add `cmd_default`**

In `bench`, add the `cmd_default` function after `cmd_clean` (around line 193):

```python
def cmd_default(args):
    """Run full pipeline: setup, correctness, synthetic, real-world (if available)."""
    cmd_setup(args)
    print()
    cmd_run_all(args)
    print()
    print("=" * 54)
    print("  Benchmarks complete! Results saved to results/")
    print()
    print("  To submit your findings:")
    print("    ./bench submit")
    print()
    print("  This will review your results for PII, then")
    print("  create a GitHub PR on your behalf.")
    print("=" * 54)
```

- [ ] **Step 2: Make `command` subparser not required**

In `build_parser()`, change line 228 from:

```python
    sub = parser.add_subparsers(dest="command", required=True)
```

to:

```python
    sub = parser.add_subparsers(dest="command")
```

- [ ] **Step 3: Update `main()` to handle no subcommand**

Replace the `main()` function:

```python
def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.command is None:
        cmd_default(args)
    else:
        COMMANDS[args.command](args)
```

- [ ] **Step 4: Test it manually**

Run: `./bench --help`
Expected: no longer shows the subcommand as required (no `{...}` in usage required positional)

Run: `./bench --hashcat-src ../hashcat setup`
Expected: still works as before (existing subcommand behavior preserved)

- [ ] **Step 5: Commit**

```bash
git add bench
git commit -m "feat: make bare ./bench run the full pipeline"
```

---

### Task 2: Improve argparse help text for all subcommands

**Files:**
- Modify: `bench:230-248` (subparser definitions)

- [ ] **Step 1: Update all `sub.add_parser` help strings**

Replace the subparser registration block (lines 230-248) with improved descriptions:

```python
    sub.add_parser("setup",
        help="Validate prerequisites (Python, hashcat binary, gh CLI, dependencies)")
    sub.add_parser("detect",
        help="Detect and print system hardware info (GPU model, driver, OS, hashcat version)")
    sub.add_parser("test",
        help="Run the pytest test suite (corpus generation, NTLM reference, validation)")
    sub.add_parser("generate-corpus",
        help="Generate NTLM test corpus (deterministic, random, and adversarial tiers)")
    sub.add_parser("run-correctness",
        help="Generate corpus and run correctness build matrix (BITSELECT on/off x VEC 1/2/4)")
    sub.add_parser("run-synthetic",
        help="Run synthetic hashcat benchmarks (default 30 trials, all modes and vec widths)")

    quick_syn = sub.add_parser("quick-synthetic",
        help="Synthetic benchmarks with 3 trials (fast iteration, not for submission)")
    quick_syn.set_defaults(trials=3)

    sub.add_parser("run-real-world",
        help="Run real-world benchmarks using rockyou.txt wordlist (requires rockyou.txt)")

    quick_rw = sub.add_parser("quick-real-world",
        help="Real-world benchmarks with 3 trials (fast iteration, not for submission)")
    quick_rw.set_defaults(trials=3)

    sub.add_parser("run-all",
        help="Run correctness + synthetic + real-world (if rockyou.txt available)")
    sub.add_parser("submit",
        help="Validate results, review for PII, and create a GitHub PR")
    sub.add_parser("clean",
        help="Remove build artifacts, generated corpus, and cached files")
```

- [ ] **Step 2: Update the top-level parser description and epilog**

Update the `build_parser()` function's `ArgumentParser` call:

```python
    parser = argparse.ArgumentParser(
        prog="bench",
        description="hashcat-benchmark-suite CLI — run './bench' with no arguments for the full pipeline.",
        epilog="Run './bench' with no arguments to execute setup + all benchmarks. "
               "Run './bench submit' to create a PR with your results.",
    )
```

- [ ] **Step 3: Verify help output**

Run: `./bench --help`
Expected: improved descriptions for all subcommands, helpful epilog text

- [ ] **Step 4: Commit**

```bash
git add bench
git commit -m "docs: improve --help text for all subcommands"
```

---

### Task 3: Rewrite README.md

**Files:**
- Modify: `README.md` (full rewrite)

- [ ] **Step 1: Replace README.md contents**

```markdown
# hashcat-benchmark-suite

Benchmark and correctness testing suite for hashcat GPU kernel optimizations.

## Quick Start

```bash
git clone https://github.com/bandrel/hashcat-benchmark-suite.git
cd hashcat-benchmark-suite
./bench
```

This validates your environment, then runs correctness tests, synthetic benchmarks (30 trials), and real-world benchmarks (if rockyou.txt is available). Expect ~20-45 minutes depending on your GPU.

## Requirements

- [uv](https://docs.astral.sh/uv/) (Python dependencies are managed automatically)
- A built hashcat binary (default: `../hashcat/hashcat`)
- GitHub CLI (`gh`) for result submission
- (Optional) `rockyou.txt` for real-world benchmarks

## Submitting Results

After benchmarks complete:

```bash
./bench submit
```

This reviews your results for PII, then creates a GitHub PR on your behalf.

## Configuration

All options can be passed as flags or set via environment variables.

| Flag | Env Variable | Default | Description |
|---|---|---|---|
| `--hashcat-src` | `HASHCAT_SRC` | `../hashcat` | Path to hashcat source tree |
| `--rockyou-path` | `ROCKYOU_PATH` | `~/wordlists/rockyou.txt` | Path to rockyou.txt wordlist |
| `--trials` | `TRIALS` | `30` | Number of trials per benchmark run |
| `--results-dir` | `RESULTS_DIR` | `results` | Output directory for results |

## Cleanup

```bash
./bench clean
```

For all available commands, run `./bench --help`.
```

- [ ] **Step 2: Review the rendered markdown mentally for correctness**

Check: no broken links, no references to removed sections, config table matches bench script defaults.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: simplify README to single-command workflow"
```
