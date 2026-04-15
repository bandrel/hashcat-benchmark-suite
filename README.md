# hashcat-benchmark-suite

Benchmark and correctness testing suite for hashcat GPU kernel optimizations, focused on Apple Silicon vectorization tuning ([hashcat#4665](https://github.com/hashcat/hashcat/pull/4665)).

## Quick Start

```bash
# Clone the suite next to your hashcat source tree
git clone https://github.com/bandrel/hashcat-benchmark-suite.git
cd hashcat-benchmark-suite

# Run the full benchmark pipeline
./bench
```

This validates your environment, then runs correctness tests, synthetic benchmarks (30 trials across 14 hash modes and Vec widths 1/2/4), and real-world benchmarks (if rockyou.txt is available). Expect ~20-45 minutes depending on your GPU.

## Requirements

- [uv](https://docs.astral.sh/uv/) (Python dependencies are managed automatically)
- A built hashcat binary with Apple Silicon tuning entries (default: `../hashcat/hashcat`)
- GitHub CLI (`gh`) — [install](https://cli.github.com/) and authenticate with `gh auth login`
- (Optional) `rockyou.txt` for real-world benchmarks

## Contributing Benchmark Results

We need results from as many Apple Silicon variants as possible (M1, M2, M3, M4 — base, Pro, Max, Ultra). Here's how to contribute:

### 1. Build hashcat from the tuning branch

```bash
git clone https://github.com/hashcat/hashcat.git
cd hashcat
git fetch origin pull/4665/head:apple-silicon-vec2-tuning
git checkout apple-silicon-vec2-tuning
make -j
cd ..
```

### 2. Clone and run the benchmark suite

```bash
git clone https://github.com/bandrel/hashcat-benchmark-suite.git
cd hashcat-benchmark-suite
./bench
```

### 3. Verify tuning entries (optional but encouraged)

```bash
./bench verify-tuning
```

This confirms your device is recognized by the `ALIAS_Apple_M` tuning group and that Vec defaults are applied correctly.

### 4. Submit your results

```bash
./bench submit
```

This will:
- Validate your results for quality and PII
- Show you `system_info.json` for review before submission
- Fork the repo if needed (external contributors)
- Create a PR with your benchmark data

If you don't have push access to this repo, the submit command automatically forks it to your GitHub account and opens a PR from there. All you need is `gh auth login`.

### What gets submitted

Results are saved under `results/<device-id>/<timestamp>/` and include:

- `system_info.json` — GPU model, core count, memory, OS, hashcat version (PII-sanitized)
- `benchmark_summary.json` — per-mode/vec statistics (mean, stdev, CI, quality flags)
- `benchmark_vec{1,2,4}.json` — raw trial data for each vector width
- Correctness test results

No hostnames, usernames, file paths, or other PII is included.

## Configuration

All options can be passed as flags or set via environment variables.

| Flag | Env Variable | Default | Description |
|---|---|---|---|
| `--hashcat-src` | `HASHCAT_SRC` | `../hashcat` | Path to hashcat source tree |
| `--rockyou-path` | `ROCKYOU_PATH` | `~/wordlists/rockyou.txt` | Path to rockyou.txt wordlist |
| `--trials` | `TRIALS` | `30` | Number of trials per benchmark run |
| `--results-dir` | `RESULTS_DIR` | `results` | Output directory for results |

## Commands

| Command | Description |
|---|---|
| `./bench` | Full pipeline: setup + correctness + synthetic + real-world |
| `./bench run-synthetic` | Synthetic benchmarks only (30 trials) |
| `./bench quick-synthetic` | Quick synthetic run (3 trials, for iteration) |
| `./bench verify-tuning` | Verify alias matching and Vec defaults |
| `./bench submit` | Validate and submit results as a PR |
| `./bench clean` | Remove build artifacts and generated corpus |

Run `./bench --help` for all commands and options.
