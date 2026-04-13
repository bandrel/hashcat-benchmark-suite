// main.swift — Host harness for NTLM MD4 native Metal benchmark
// Usage: ntlm_bench [--candidates N] [--trials N] [--warmup N] [--verify] [--json]

import Foundation
import Metal

// ---------------------------------------------------------------------------
// Command-line argument parsing
// ---------------------------------------------------------------------------
struct Config {
    var candidates: Int = 10_000_000
    var trials: Int = 30
    var warmup: Int = 2
    var verify: Bool = false
    var json: Bool = false
    var metallibPath: String = "ntlm_md4.metallib"
}

func parseArgs() -> Config {
    var config = Config()
    var args = CommandLine.arguments.dropFirst()
    while let arg = args.first {
        args = args.dropFirst()
        switch arg {
        case "--candidates":
            if let val = args.first, let n = Int(val) { config.candidates = n; args = args.dropFirst() }
        case "--trials":
            if let val = args.first, let n = Int(val) { config.trials = n; args = args.dropFirst() }
        case "--warmup":
            if let val = args.first, let n = Int(val) { config.warmup = n; args = args.dropFirst() }
        case "--verify":
            config.verify = true
        case "--json":
            config.json = true
        case "--metallib":
            if let val = args.first { config.metallibPath = val; args = args.dropFirst() }
        default:
            break
        }
    }
    return config
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
func hexString(_ value: UInt32) -> String {
    // Output as little-endian hex (byte-swapped) to match conventional hash display
    let bytes = withUnsafeBytes(of: value.littleEndian) { Array($0) }
    return bytes.map { String(format: "%02x", $0) }.joined()
}

func hexDigest(_ d: (UInt32, UInt32, UInt32, UInt32)) -> String {
    return hexString(d.0) + hexString(d.1) + hexString(d.2) + hexString(d.3)
}

func packPassword(_ password: String) -> (UInt32, UInt32, UInt32, UInt32, UInt32) {
    // Pack password bytes into 4 uint32s (little-endian), return (w0, w1, w2, w3, length)
    let bytes = Array(password.utf8)
    let len = min(bytes.count, 16)
    var words: [UInt32] = [0, 0, 0, 0]
    for i in 0..<len {
        words[i / 4] |= UInt32(bytes[i]) << (UInt32(i % 4) * 8)
    }
    return (words[0], words[1], words[2], words[3], UInt32(len))
}

// ---------------------------------------------------------------------------
// Software MD4 for verification
// ---------------------------------------------------------------------------
func softwareMD4(_ password: String) -> (UInt32, UInt32, UInt32, UInt32) {
    // Convert to UTF-16LE
    let bytes = Array(password.utf8)
    var utf16le: [UInt8] = []
    for b in bytes {
        utf16le.append(b)
        utf16le.append(0)
    }
    let bitLen = UInt64(utf16le.count * 8)

    // Pad
    utf16le.append(0x80)
    while utf16le.count % 64 != 56 {
        utf16le.append(0)
    }
    // Append length as 64-bit little-endian
    for i in 0..<8 {
        utf16le.append(UInt8((bitLen >> (i * 8)) & 0xFF))
    }

    // Parse into uint32 words
    var w = [UInt32](repeating: 0, count: 16)
    for i in 0..<16 {
        let base = i * 4
        w[i] = UInt32(utf16le[base])
             | (UInt32(utf16le[base + 1]) << 8)
             | (UInt32(utf16le[base + 2]) << 16)
             | (UInt32(utf16le[base + 3]) << 24)
    }

    func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 {
        return (x << n) | (x >> (32 - n))
    }
    func F(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { return (x & y) | (~x & z) }
    func G(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { return (x & y) | (x & z) | (y & z) }
    func H(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { return x ^ y ^ z }

    var a: UInt32 = 0x67452301
    var b: UInt32 = 0xefcdab89
    var c: UInt32 = 0x98badcfe
    var d: UInt32 = 0x10325476

    // Round 1
    let r1order = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    let r1shifts: [UInt32] = [3,7,11,19,3,7,11,19,3,7,11,19,3,7,11,19]
    for i in 0..<16 {
        let f = F(b, c, d) &+ a &+ w[r1order[i]] &+ 0x00000000
        a = rotl(f, r1shifts[i])
        let tmp = d; d = c; c = b; b = a; a = tmp
    }

    // Round 2
    let r2order = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
    let r2shifts: [UInt32] = [3,5,9,13,3,5,9,13,3,5,9,13,3,5,9,13]
    for i in 0..<16 {
        let g = G(b, c, d) &+ a &+ w[r2order[i]] &+ 0x5a827999
        a = rotl(g, r2shifts[i])
        let tmp = d; d = c; c = b; b = a; a = tmp
    }

    // Round 3
    let r3order = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
    let r3shifts: [UInt32] = [3,9,11,15,3,9,11,15,3,9,11,15,3,9,11,15]
    for i in 0..<16 {
        let h = H(b, c, d) &+ a &+ w[r3order[i]] &+ 0x6ed9eba1
        a = rotl(h, r3shifts[i])
        let tmp = d; d = c; c = b; b = a; a = tmp
    }

    a = a &+ 0x67452301
    b = b &+ 0xefcdab89
    c = c &+ 0x98badcfe
    d = d &+ 0x10325476

    return (a, b, c, d)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
let config = parseArgs()

guard let device = MTLCreateSystemDefaultDevice() else {
    fputs("Error: No Metal device found\n", stderr)
    exit(1)
}

guard let commandQueue = device.makeCommandQueue() else {
    fputs("Error: Failed to create command queue\n", stderr)
    exit(1)
}

// Load metallib
let metallibURL = URL(fileURLWithPath: config.metallibPath)
let library: MTLLibrary
do {
    library = try device.makeLibrary(URL: metallibURL)
} catch {
    fputs("Error: Failed to load metallib from \(config.metallibPath): \(error)\n", stderr)
    exit(1)
}

// ---------------------------------------------------------------------------
// Verify mode
// ---------------------------------------------------------------------------
if config.verify {
    // Test 1: "hashcat" → known hash b4b9b02e6f09a9bd760f388b67351e2b
    let knownHash = "b4b9b02e6f09a9bd760f388b67351e2b"

    // Software verification first
    let swDigest = softwareMD4("hashcat")
    let swHex = hexDigest(swDigest)
    print("Software MD4 of 'hashcat': \(swHex)")
    if swHex != knownHash {
        print("FAIL: Software MD4 mismatch! Expected \(knownHash)")
        exit(1)
    }
    print("Software MD4: PASS")

    // GPU verification
    guard let benchFn = library.makeFunction(name: "ntlm_bench") else {
        fputs("Error: ntlm_bench function not found in metallib\n", stderr)
        exit(1)
    }
    let pipelineState: MTLComputePipelineState
    do {
        pipelineState = try device.makeComputePipelineState(function: benchFn)
    } catch {
        fputs("Error: Failed to create pipeline: \(error)\n", stderr)
        exit(1)
    }

    // Test multiple passwords
    let testCases: [(String, String)] = [
        ("hashcat", "b4b9b02e6f09a9bd760f388b67351e2b"),
        ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),           // empty password
        ("a", "186cb09181e2c2ecaac768c47c729904"),
        ("abc", "e0fba38268d0ec66ef1cb452d5885e53"),
        ("password", "8846f7eaee8fb117ad06bdd830b7586c"),
    ]

    let numCandidates = testCases.count
    let candidateBuf = device.makeBuffer(length: numCandidates * MemoryLayout<SIMD4<UInt32>>.stride,
                                          options: .storageModeShared)!
    let lengthBuf = device.makeBuffer(length: numCandidates * MemoryLayout<UInt32>.stride,
                                       options: .storageModeShared)!
    let digestBuf = device.makeBuffer(length: numCandidates * MemoryLayout<SIMD4<UInt32>>.stride,
                                       options: .storageModeShared)!

    let candPtr = candidateBuf.contents().bindMemory(to: SIMD4<UInt32>.self, capacity: numCandidates)
    let lenPtr = lengthBuf.contents().bindMemory(to: UInt32.self, capacity: numCandidates)

    for (i, (pw, _)) in testCases.enumerated() {
        let packed = packPassword(pw)
        candPtr[i] = SIMD4<UInt32>(packed.0, packed.1, packed.2, packed.3)
        lenPtr[i] = packed.4
    }

    guard let cmdBuf = commandQueue.makeCommandBuffer(),
          let encoder = cmdBuf.makeComputeCommandEncoder() else {
        fputs("Error: Failed to create command buffer/encoder\n", stderr)
        exit(1)
    }

    encoder.setComputePipelineState(pipelineState)
    encoder.setBuffer(candidateBuf, offset: 0, index: 0)
    encoder.setBuffer(lengthBuf, offset: 0, index: 1)
    encoder.setBuffer(digestBuf, offset: 0, index: 2)

    let threadgroupSize = MTLSize(width: min(numCandidates, 256), height: 1, depth: 1)
    let gridSize = MTLSize(width: numCandidates, height: 1, depth: 1)
    encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
    encoder.endEncoding()
    cmdBuf.commit()
    cmdBuf.waitUntilCompleted()

    let digestPtr = digestBuf.contents().bindMemory(to: SIMD4<UInt32>.self, capacity: numCandidates)
    var allPassed = true
    for (i, (pw, expectedHex)) in testCases.enumerated() {
        let d = digestPtr[i]
        let got = hexDigest((d.x, d.y, d.z, d.w))
        let ok = got == expectedHex
        print("GPU MD4 of '\(pw)': \(got) \(ok ? "PASS" : "FAIL (expected \(expectedHex))")")
        if !ok { allPassed = false }
    }

    if allPassed {
        print("\nAll verification tests PASSED")
        exit(0)
    } else {
        print("\nSome verification tests FAILED")
        exit(1)
    }
}

// ---------------------------------------------------------------------------
// Benchmark mode
// ---------------------------------------------------------------------------
guard let benchFn = library.makeFunction(name: "ntlm_bench") else {
    fputs("Error: ntlm_bench function not found in metallib\n", stderr)
    exit(1)
}
let pipelineState: MTLComputePipelineState
do {
    pipelineState = try device.makeComputePipelineState(function: benchFn)
} catch {
    fputs("Error: Failed to create pipeline: \(error)\n", stderr)
    exit(1)
}

let numCandidates = config.candidates
// Round up to multiple of 256
let alignedCandidates = ((numCandidates + 255) / 256) * 256

let candidateBuf = device.makeBuffer(length: alignedCandidates * MemoryLayout<SIMD4<UInt32>>.stride,
                                      options: .storageModeShared)!
let lengthBuf = device.makeBuffer(length: alignedCandidates * MemoryLayout<UInt32>.stride,
                                   options: .storageModeShared)!
let digestBuf = device.makeBuffer(length: alignedCandidates * MemoryLayout<SIMD4<UInt32>>.stride,
                                   options: .storageModeShared)!

// Generate candidate passwords: "password0000000", "password0000001", ...
if !config.json {
    print("Generating \(numCandidates) candidate passwords...")
}

let candPtr = candidateBuf.contents().bindMemory(to: SIMD4<UInt32>.self, capacity: alignedCandidates)
let lenPtr = lengthBuf.contents().bindMemory(to: UInt32.self, capacity: alignedCandidates)

// "password" = [0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64] = 0x73736170, 0x64726f77
let baseW0: UInt32 = 0x73736170  // "pass" little-endian
let baseW1: UInt32 = 0x64726f77  // "word" little-endian
let pwLen: UInt32 = 15  // "password" (8) + 7 digit suffix = 15 chars

for i in 0..<alignedCandidates {
    let suffix = String(format: "%07d", i % 10_000_000)
    let suffixBytes = Array(suffix.utf8)
    // Pack suffix into w2, w3
    var w2: UInt32 = 0
    var w3: UInt32 = 0
    for j in 0..<min(suffixBytes.count, 4) {
        w2 |= UInt32(suffixBytes[j]) << (UInt32(j) * 8)
    }
    for j in 4..<min(suffixBytes.count, 8) {
        w3 |= UInt32(suffixBytes[j]) << (UInt32(j - 4) * 8)
    }
    candPtr[i] = SIMD4<UInt32>(baseW0, baseW1, w2, w3)
    lenPtr[i] = pwLen
}

if !config.json {
    print("Running \(config.warmup) warmup + \(config.trials) benchmark trials with \(numCandidates) candidates each...")
    print("Device: \(device.name)")
    print("Threadgroup size: 256")
    print("Grid size: \(alignedCandidates)")
    print("")
}

let threadgroupSize = MTLSize(width: 256, height: 1, depth: 1)
let gridSize = MTLSize(width: alignedCandidates, height: 1, depth: 1)

var trialTimes: [Double] = []
var trialHashes: [Double] = []

for trial in 0..<(config.warmup + config.trials) {
    guard let cmdBuf = commandQueue.makeCommandBuffer(),
          let encoder = cmdBuf.makeComputeCommandEncoder() else {
        fputs("Error: Failed to create command buffer/encoder\n", stderr)
        exit(1)
    }

    encoder.setComputePipelineState(pipelineState)
    encoder.setBuffer(candidateBuf, offset: 0, index: 0)
    encoder.setBuffer(lengthBuf, offset: 0, index: 1)
    encoder.setBuffer(digestBuf, offset: 0, index: 2)
    encoder.dispatchThreads(gridSize, threadsPerThreadgroup: threadgroupSize)
    encoder.endEncoding()

    cmdBuf.commit()
    cmdBuf.waitUntilCompleted()

    let gpuTime = cmdBuf.gpuEndTime - cmdBuf.gpuStartTime
    let hashesPerSec = Double(numCandidates) / gpuTime

    if trial >= config.warmup {
        trialTimes.append(gpuTime)
        trialHashes.append(hashesPerSec)

        if !config.json {
            let trialNum = trial - config.warmup + 1
            print(String(format: "Trial %2d: %.4f ms  %.2f MH/s",
                         trialNum, gpuTime * 1000.0, hashesPerSec / 1_000_000.0))
        }
    } else if !config.json {
        print(String(format: "Warmup %d: %.4f ms", trial + 1, gpuTime * 1000.0))
    }
}

// Statistics
let meanTime = trialTimes.reduce(0, +) / Double(trialTimes.count)
let meanHS = trialHashes.reduce(0, +) / Double(trialHashes.count)
let variance = trialHashes.map { ($0 - meanHS) * ($0 - meanHS) }.reduce(0, +) / Double(trialHashes.count)
let stdevHS = variance.squareRoot()

if config.json {
    let trialsJSON = trialHashes.map { String(format: "%.0f", $0) }.joined(separator: ", ")
    print("""
    {
      "device": "\(device.name)",
      "candidates": \(numCandidates),
      "warmup_trials": \(config.warmup),
      "benchmark_trials": \(config.trials),
      "threadgroup_size": 256,
      "trials_hs": [\(trialsJSON)],
      "mean_hs": \(String(format: "%.0f", meanHS)),
      "stdev_hs": \(String(format: "%.0f", stdevHS)),
      "mean_time_ms": \(String(format: "%.4f", meanTime * 1000.0)),
      "mean_mhs": \(String(format: "%.2f", meanHS / 1_000_000.0))
    }
    """)
} else {
    print("")
    print(String(format: "Mean kernel time:  %.4f ms", meanTime * 1000.0))
    print(String(format: "Mean throughput:    %.2f MH/s", meanHS / 1_000_000.0))
    print(String(format: "Stdev throughput:   %.2f MH/s", stdevHS / 1_000_000.0))
    print(String(format: "Candidates/trial:   %d", numCandidates))
}
