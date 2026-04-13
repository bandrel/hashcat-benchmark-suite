// main.swift — Host harness for Metal NTLM PoC benchmark
// Matches hashcat's a3-optimized architecture: inner loop, Vec:1 and Vec:2

import Foundation
import Metal

// ── Configuration ──────────────────────────────────────────────────────────
let THREADGROUP_SIZE = 256
let DEFAULT_NUM_THREADS = 480 * THREADGROUP_SIZE  // 480 threadgroups
let DEFAULT_IL_CNT: UInt32 = 1024                 // inner loop count
let DEFAULT_TRIALS = 30
let DEFAULT_WARMUP = 5

// ── Argument parsing ───────────────────────────────────────────────────────
var numThreads = DEFAULT_NUM_THREADS
var ilCnt = DEFAULT_IL_CNT
var trials = DEFAULT_TRIALS
var warmup = DEFAULT_WARMUP
var useVec2 = false
var jsonOutput = false

var argIdx = 1
while argIdx < CommandLine.arguments.count {
    let arg = CommandLine.arguments[argIdx]
    switch arg {
    case "--threads":  argIdx += 1; numThreads = Int(CommandLine.arguments[argIdx])!
    case "--il-cnt":   argIdx += 1; ilCnt = UInt32(CommandLine.arguments[argIdx])!
    case "--trials":   argIdx += 1; trials = Int(CommandLine.arguments[argIdx])!
    case "--warmup":   argIdx += 1; warmup = Int(CommandLine.arguments[argIdx])!
    case "--vec2":     useVec2 = true
    case "--json":     jsonOutput = true
    default: break
    }
    argIdx += 1
}

let totalCandidates = numThreads * Int(ilCnt)
let vec = useVec2 ? 2 : 1

// ── Metal setup ────────────────────────────────────────────────────────────
guard let device = MTLCreateSystemDefaultDevice() else { fatalError("No Metal device") }
let queue = device.makeCommandQueue()!

let metalURL = URL(fileURLWithPath: "ntlm_md4.metallib")
let library: MTLLibrary
if FileManager.default.fileExists(atPath: metalURL.path) {
    library = try! device.makeLibrary(URL: metalURL)
} else {
    let source = try! String(contentsOf: URL(fileURLWithPath: "ntlm_md4.metal"))
    library = try! device.makeLibrary(source: source, options: nil)
}

let kernelName = useVec2 ? "ntlm_bench_v2" : "ntlm_bench_v1"
guard let function = library.makeFunction(name: kernelName) else {
    fatalError("Kernel \(kernelName) not found in library")
}
let pipeline = try! device.makeComputePipelineState(function: function)

if !jsonOutput {
    print("Device: \(device.name)")
    print("Kernel: \(kernelName)")
    print("Threads: \(numThreads) (\(numThreads / THREADGROUP_SIZE) threadgroups x \(THREADGROUP_SIZE))")
    print("IL_CNT: \(ilCnt)")
    print("Vec: \(vec)")
    print("Total candidates/dispatch: \(totalCandidates)")
    print("Trials: \(trials) (warmup: \(warmup))")
    print()
}

// ── Buffer setup ───────────────────────────────────────────────────────────
// base_words: [numThreads][16] uint32 — UTF-16LE expanded password + padding
// Using "password" (8 chars): UTF-16LE fills w[0..3], w[4]=0x80, w[14]=128 bits
let baseWordsSize = numThreads * 16 * MemoryLayout<UInt32>.size
let baseWordsBuf = device.makeBuffer(length: baseWordsSize, options: .storageModeShared)!
let baseWordsPtr = baseWordsBuf.contents().bindMemory(to: UInt32.self, capacity: numThreads * 16)

let baseWords: [UInt32] = [
    0x00610070,  // w0: 'p','a' UTF-16LE (left part, will be OR'd with w0r)
    0x00730073,  // w1: 's','s'
    0x006f0077,  // w2: 'w','o'
    0x00640072,  // w3: 'r','d'
    0x00000080,  // w4: 0x80 padding
    0, 0, 0, 0, 0, 0, 0, 0, 0,
    128,         // we: 8 * 2 * 8 = 128 bits
    0            // wf
]
for t in 0..<numThreads {
    for w in 0..<16 { baseWordsPtr[t * 16 + w] = baseWords[w] }
}

// words_buf_r: varying right-side bits for w[0] per inner loop iteration
// Sequential values masked to not overlap the base password's w[0] bits
let wbrCount = useVec2 ? Int(ilCnt) : Int(ilCnt)
let wbrSize = wbrCount * MemoryLayout<UInt32>.size
let wbrBuf = device.makeBuffer(length: wbrSize, options: .storageModeShared)!
let wbrPtr = wbrBuf.contents().bindMemory(to: UInt32.self, capacity: wbrCount)
for j in 0..<wbrCount {
    wbrPtr[j] = UInt32(j & 0x00FF0000)  // bits in positions that don't overlap base w0
}

// Digest output buffer — one per thread (accumulator), not one per candidate
let digestSize = numThreads * 4 * MemoryLayout<UInt32>.size
let digestBuf = device.makeBuffer(length: digestSize, options: .storageModeShared)!

// IL_CNT constant buffer
var ilCntVal = ilCnt
let ilCntBuf = device.makeBuffer(bytes: &ilCntVal, length: MemoryLayout<UInt32>.size, options: .storageModeShared)!

// ── Benchmark ──────────────────────────────────────────────────────────────
var speeds: [Double] = []
let threadgroupSize = MTLSize(width: THREADGROUP_SIZE, height: 1, depth: 1)
let gridSize = MTLSize(width: numThreads, height: 1, depth: 1)

for trial in 0..<(warmup + trials) {
    let cmdBuf = queue.makeCommandBuffer()!
    let encoder = cmdBuf.makeComputeCommandEncoder()!
    encoder.setComputePipelineState(pipeline)
    encoder.setBuffer(baseWordsBuf, offset: 0, index: 0)
    encoder.setBuffer(wbrBuf, offset: 0, index: 1)
    encoder.setBuffer(digestBuf, offset: 0, index: 2)
    encoder.setBuffer(ilCntBuf, offset: 0, index: 3)
    encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
    encoder.endEncoding()
    cmdBuf.commit()
    cmdBuf.waitUntilCompleted()

    let gpuTime = cmdBuf.gpuEndTime - cmdBuf.gpuStartTime
    if gpuTime > 0 {
        let hs = Double(totalCandidates) / gpuTime
        if trial >= warmup {
            speeds.append(hs)
            if !jsonOutput {
                print(String(format: "  Trial %2d: %.2f GH/s (%.1f ms)",
                      trial - warmup + 1, hs / 1e9, gpuTime * 1000))
            }
        }
    }
}

// ── Results ────────────────────────────────────────────────────────────────
let mean = speeds.reduce(0, +) / Double(speeds.count)
let variance = speeds.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(max(speeds.count - 1, 1))
let stdev = variance.squareRoot()

if jsonOutput {
    let trialStrs = speeds.map { String(format: "%.0f", $0) }.joined(separator: ", ")
    print("""
    {
      "device": "\(device.name)",
      "kernel": "\(kernelName)",
      "vec": \(vec),
      "threads": \(numThreads),
      "il_cnt": \(ilCnt),
      "total_candidates": \(totalCandidates),
      "warmup_trials": \(warmup),
      "benchmark_trials": \(speeds.count),
      "trials_hs": [\(trialStrs)],
      "mean_hs": \(String(format: "%.0f", mean)),
      "stdev_hs": \(String(format: "%.0f", stdev)),
      "mean_ghs": \(String(format: "%.2f", mean / 1e9))
    }
    """)
} else {
    print()
    print(String(format: "Mean: %.2f GH/s ± %.2f GH/s (CV: %.1f%%)",
          mean / 1e9, stdev / 1e9, stdev / mean * 100))
    print("hashcat reference: ~34.6 GH/s (Vec:2, Accel:480, Loops:1024)")
    print(String(format: "Ratio: %.2fx", 34.6e9 / mean))
}
