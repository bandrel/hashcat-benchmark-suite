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
