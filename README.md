# BoltLock

An embedded secrets management vault and tamper evident audit log engine written in Go. 

## Architectural Invariant & Threat Model

**BoltLock** is engineered around a strict zero persistence memory boundary: the decrypted master key exists strictly within volatile execution space (RAM) and is never written to persistent block storage. 

To defend against runtime forensic extraction, memory scraping vectors, and inadvertent disk leakage, the application programmatically manipulates host kernel invariants via direct low level system calls (`syscall`) at process initialization.


```

```
   [ App Boot ] ──► Call hardenProcess()
                         │
                         ├──► Setrlimit(RLIMIT_CORE, 0)   ──► Blocks Crash Core Dumps
                         └──► Syscall(PR_SET_DUMPABLE, 0) ──► Blocks live ptrace/gdb attach
                                 │
                    [ Trigger POST /sys/unseal ]
                                 │
                         ├──► Derive Master Key via Argon2id
                         └──► Mlock(masterKey)            ──► Pins bytes to Physical RAM (No Swap)
                                 │
                     [ Trigger POST /sys/seal ]
                                 │
                         ├──► Manual Zeroization Loop    ──► Destructive memory overwrite (No GC stale bytes)
                         └──► Munlock(masterKey)          ──► Release RAM allocation

```

```

---

## Hardened Core Features

### 1. Anti-Swap Memory Pinning (`mlock`)
To prevent the host kernel's Virtual Memory Manager from moving memory pages holding plaintext keys out to a non volatile disk swap partition during periods of high memory pressure, BoltLock invokes `syscall.Mlock` at the page table level. Sensitive key allocations are permanently pinned to physical hardware RAM for the entire duration of the unsealed session lifecycle.

### 2. Runtime Dump Suppression (`RLIMIT_CORE` & `PR_SET_DUMPABLE`)
- **Core Dump Neutralization:** Invokes `syscall.Setrlimit` to set `RLIMIT_CORE` to zero bytes, ensuring that an unexpected application panic, abort signal, or segmentation fault cannot write a plaintext memory snapshot to disk.
- **Live Attacker Mitigation:** Executes a `SYS_PRCTL` system call with `PR_SET_DUMPABLE=0`. This instructs the kernel to drop the process's dumpable flag, blocking unauthorized same-user `ptrace` attachments, live `gdb` memory abstractions, and `/proc/[pid]/mem` scraping attempts.

### 3. Deterministic In Memory Zeroization
Setting active references to `nil` in garbage-collected runtimes like Go leaves original cryptographic data intact on the heap until an indeterminate collection cycle completes. BoltLock implements automated, manual byte overwriting loops to explicitly zero out (`0x00`) memory slices holding secret material immediately upon triggering a system seal operation bypassing raw data remnancy risks.

### 4. Cryptographic Audit Chaining & Envelope Isolation
- **Tamper Evident Append Only Logs:** Every transaction is tracked via a hash chained audit architecture where each block stores an `HMAC-SHA256` signature over its own fields combined with the signature of the preceding block.
- **Envelope Encryption Matrix:** Secrets are encrypted at rest using isolated, per secret Data Encryption Keys (DEKs) running on authenticated `AES-256-GCM` blocks. The DEKs are themselves encrypted via the volatile in memory Master Key derived from user passphrases via `Argon2id`.


## Development Environment
* **Language Layer:** Go 1.2+
* **Target Kernel Architecture:** Linux / POSIX Compliant
* **Database Driver:** `go.etcd.io/bbolt`
* **Cryptographic Extensions:** `golang.org/x/crypto/argon2`
