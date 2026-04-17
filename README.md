# hashcat-benchmark-suite

Benchmark and correctness testing suite for hashcat GPU kernel optimizations, focused on Apple Silicon vectorization tuning ([hashcat#4665](https://github.com/hashcat/hashcat/pull/4665)).

We need results from as many Apple Silicon variants as possible (M1, M2, M3, M4 — base, Pro, Max, Ultra).

## Requirements

- [uv](https://docs.astral.sh/uv/) — Python dependencies are managed automatically
- A built hashcat binary from the tuning branch (see step 1 below)
- (Optional) GitHub CLI (`gh`) — [install](https://cli.github.com/) and `gh auth login` for automatic PR submission. Without it, `./bench submit` generates a Markdown file with manual instructions.
- (Optional) `rockyou.txt` at `~/wordlists/rockyou.txt` for real-world benchmarks

## Running the suite

### 1. Build hashcat from the tuning branch

```bash
git clone https://github.com/hashcat/hashcat.git
cd hashcat
git fetch origin pull/4665/head:apple-silicon-vec2-tuning
git checkout apple-silicon-vec2-tuning
make -j$(sysctl -n hw.ncpu)
cd ..
```

### 2. Clone and run the benchmark suite

```bash
git clone https://github.com/bandrel/hashcat-benchmark-suite.git
cd hashcat-benchmark-suite
./bench
```

`./bench` validates your environment, then runs correctness tests, synthetic benchmarks (30 trials across 71 hash modes and Vec widths 1/2/4/8), and real-world benchmarks (if rockyou.txt is available). Expect ~20-45 minutes depending on your GPU.

On macOS, `./bench` automatically passes `-d 1` to hashcat so kernels build against Metal — hashcat otherwise auto-selects the Apple OpenCL device on Apple Silicon and fails with a kernel build error. Override with `--device N` if you need a different device.

### 3. Verify tuning entries (optional)

```bash
./bench verify-tuning
```

Confirms your device is recognized by the `ALIAS_Apple_M` tuning group and that Vec defaults are applied correctly.

### 4. Submit your results

```bash
./bench submit
```

Validates results for quality and PII, shows you `system_info.json` before submission, forks the repo if needed, and creates a PR with your benchmark data. All you need is `gh auth login`.

## What gets submitted

Results are saved under `results/<device-id>/<timestamp>/`:

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
| `--device` | `DEVICE` | `1` on macOS, unset elsewhere | Hashcat backend device id (`-d`) |

## Commands

| Command | Description |
|---|---|
| `./bench` | Full pipeline: setup + correctness + synthetic + real-world |
| `./bench run-synthetic` | Synthetic benchmarks only (30 trials) |
| `./bench quick-synthetic` | Quick synthetic run (3 trials, for iteration) |
| `./bench verify-tuning` | Verify alias matching and Vec defaults |
| `./bench submit` | Validate and submit results as a PR |

Run `./bench --help` for all commands and options.
