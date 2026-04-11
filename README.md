# hashcat-benchmark-suite

Benchmark and correctness testing suite for hashcat GPU kernel optimizations.

## Quick Start

```bash
# Clone
git clone https://github.com/bandrel/hashcat-benchmark-suite.git
cd hashcat-benchmark-suite

# Verify prerequisites
make setup

# Run all tests (correctness + synthetic; real-world if rockyou.txt is available)
make run-all

# Submit results
make submit
```

## Requirements

- Python 3.8+
- A built hashcat binary (default: `../hashcat/hashcat`)
- GitHub CLI (`gh`) for result submission
- (Optional) `rockyou.txt` for real-world benchmarks

## Configuration

All variables can be overridden via environment or on the `make` command line.

| Variable | Default | Description |
|---|---|---|
| `PYTHON` | `python3` | Python interpreter |
| `HASHCAT_SRC` | `../hashcat` | Path to hashcat source tree |
| `HASHCAT_BIN` | `$(HASHCAT_SRC)/hashcat` | Path to hashcat binary |
| `ROCKYOU_PATH` | `$(HOME)/wordlists/rockyou.txt` | Path to rockyou.txt wordlist |
| `TRIALS` | `30` | Number of trials for full benchmark runs |
| `QUICK_TRIALS` | `3` | Number of trials for quick benchmark runs |
| `RESULTS_DIR` | `results` | Output directory for results |

Example:

```bash
make run-synthetic HASHCAT_BIN=/opt/hashcat/hashcat TRIALS=10
```

## Targets

| Target | Description |
|---|---|
| `make help` | Print usage and configuration |
| `make setup` | Validate prerequisites |
| `make detect` | Detect system hardware |
| `make test` | Run pytest suite |
| `make generate-corpus` | Generate test corpus |
| `make run-correctness` | Run correctness tests |
| `make run-synthetic` | Synthetic benchmarks (30 trials) |
| `make quick-synthetic` | Synthetic benchmarks (3 trials) |
| `make run-real-world` | Real-world benchmarks with rockyou.txt |
| `make quick-real-world` | Real-world benchmarks, quick mode |
| `make run-all` | Correctness + synthetic + real-world |
| `make submit` | Package and submit results |
| `make clean` | Remove generated files |

## Directory Structure

```
.github/workflows/   CI configuration
schemas/             JSON schemas for result validation
tools/               Python scripts (detect, generate, run, submit)
tests/               pytest test suite
corpus/              Generated test inputs (gitignored)
results/             Benchmark output (gitignored)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run `make setup` to verify your environment
4. Run `make test` before submitting
5. Open a pull request
