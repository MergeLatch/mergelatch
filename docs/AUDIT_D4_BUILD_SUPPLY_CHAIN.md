# Audit D-4: Scanner Build-Time Dependency and Supply-Chain Evaluation

**Date:** 2026-11-15  
**Starting main commit:** `78ab868e61d7dfda6b55b01941dd7c026c855a53`  
**Status:** maintainer audit and decision record for Decision D-4 (and finding F-06).  
**Scope:** evaluate the scanner's build-time dependency and supply-chain risks, assess cold/warm build performance and failure modes on supported GitHub-hosted runners, compare source compilation with verified prebuilt binaries, and determine whether the advisory GitHub Action should continue building from source or move to prebuilt binaries.

---

## Phase 1: Audit of the Existing Build

### 1. Build Architecture and File Inspection

The build process for the advisory Action was inspected across the following components:

- **`action/build.sh`**: Executed under `bash` with `set -euo pipefail`. Enforces that it is started exclusively by the trusted Python helper (`MLA_CONTROLLED_ENV == "1"`). Asserts that `rustup` and `cargo` resolve strictly to `${CARGO_HOME}/bin/{tool}`. Changes directory to `${MLA_ACTION_ROOT}` before invoking any toolchain command so that configuration files in the scanned workspace are never read. Invokes `rustup toolchain install --no-self-update` and `CARGO_TARGET_DIR="${target_dir}" cargo build --locked --release -p mergelatch-cli`. Records the toolchain version to `${MLA_STATE_DIR}/rustc-version.txt` and the output executable path to `${MLA_STATE_DIR}/binary-path.txt`.
- **`action/mergelatch_action.py`**:
  - `prepare()`: Runs in Python isolated mode (`/usr/bin/python3 -I`). Validates that the runner is a GitHub-hosted Ubuntu x86-64 runner image, checks that loader variables (`LD_*`, `GCONV_PATH`) are absent, checks for supported events (strictly `pull_request` per D-1), checks for the presence of the scanner source in `${MLA_ACTION_PATH}`, and resolves the scan directory within the workspace.
  - `trusted_environment()`: Constructs a clean process environment from scratch using fixed paths (`PATH`, `CARGO_HOME`, `RUSTUP_HOME`, `LANG=C.UTF-8`, and `HOME` resolved from `pwd.getpwuid()`, not the inherited `HOME` variable). Replaces and reports all inherited build settings (`CARGO_*`, `RUST*`, `BASH_ENV`, `PYTHON*`, etc.).
  - `build()`: Runs `build.sh` via `run_build_process()` in a fresh session and process group (`start_new_session=True`). Enforces a 1,500-second timeout, sending `SIGKILL` to the entire process group before reaping the script child (F-08 fix).
  - `scan()`: Executes the binary identified in `binary-path.txt` within the private state directory, passing only the validated scan directory path argument. Applies a file-size output limit (`RLIMIT_FSIZE`) of 16 MiB and a 300-second execution timeout.
  - `report()`: Evaluates the outcome. If `MLA_BUILD_OUTCOME != "success"`, or if `scan-exit-code.txt` indicates failure, it marks the status as `error`, logs an `::error` annotation, writes `status=error`, and exits with code 1.
- **`rust-toolchain.toml`**: Specifies channel `"1.99.1"`, profile `"minimal"`, and components `["rustfmt", "clippy"]`. Read directly by `rustup toolchain install`.
- **`Cargo.lock` and `Cargo.toml`**: Cargo workspace resolver version 3 (`resolver = "3"`). Workspace defines `unsafe_code = "forbid"` in `[workspace.lints.rust]`. Root packages: `crates/core` (`mergelatch-core`) and `crates/cli` (`mergelatch-cli`).
- **Workflows (`action-checks.yml`, `rust.yml`)**: Run on unprivileged triggers (`pull_request` to `main`), read-only `contents: read` permissions, `persist-credentials: false`. Upstream linter binaries (`actionlint`, `shellcheck`) are verified with hardcoded SHA-256 digests before execution.

---

### 2. Recalculated Dependency Inventory

The production build of the scanner CLI for `x86_64-unknown-linux-gnu` compiles only `mergelatch-cli` in release mode (`cargo build --locked --release -p mergelatch-cli`). Dev-dependencies (such as `tempfile` and its sub-dependencies `fastrand`, `libc`, `getrandom`) and Windows-only crates (`windows-sys`, `winx`, `windows_x86_64_*`) present in `Cargo.lock` are not compiled.

- **Total packages in `Cargo.lock`:** 78
- **Total packages in production build tree:** 47
  - **Workspace packages:** 2 (`mergelatch-cli`, `mergelatch-core`)
  - **External crates from `crates.io`:** 45
    - **Proc-macro crates (executed by `rustc` during macro expansion):** 2
    - **Crates with custom build scripts (`build.rs`, executed by Cargo during build):** 12 crates (covering 13 package instances due to two distinct versions of `io-lifetimes`: 2.0.4 and 3.0.1)
    - **Runtime-only registry libraries:** 31
- **Total third-party crates executing code at build time:** 14 distinct crates (15 package instances).

#### Complete Production Dependency Inventory Table

All registry crates originate from `registry+https://github.com/rust-lang/crates.io-index`. Every checksum is enforced by `Cargo.lock` with `--locked`.

| Crate | Version | Category / Role | Executed at Build Time? | Checksum (SHA-256) |
|---|---|---|---|---|
| `ambient-authority` | `0.0.2` | Runtime library | No | `e9d4ee0d472d1cd2e28c97dfa124b3d8d992e10eb0a035f33f5d12e3a177ba3b` |
| `anstream` | `1.0.0` | Runtime library | No | `824a212faf96e9acacdbd09febd34438f8f711fb84e09a8916013cd7815ca28d` |
| `anstyle` | `1.0.14` | Runtime library | No | `940b3a0ca603d1eade50a4846a2afffd5ef57a9feac2c0e2ec2e14f9ead76000` |
| `anstyle-parse` | `1.0.0` | Runtime library | No | `52ce7f38b242319f7cabaa6813055467063ecdc9d355bbb4ce0c68908cd8130e` |
| `anstyle-query` | `1.1.5` | Runtime library | No | `40c48f72fd53cd289104fc64099abca73db4166ad86ea0b4341abe65af83dadc` |
| `arraydeque` | `0.5.1` | Runtime library | No | `7d902e3d592a523def97af8f317b08ce16b7ab854c1985a0c671e6f15cebc236` |
| `bitflags` | `2.13.2` | Runtime library | No | `3ded4057c258ba199e2d26386d3af3780957ecaee6c4ef4041c6b4b8b97c0b06` |
| `cap-primitives` | `4.0.3` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `8b5f74729fd2f44701d1a8eb47e906cdb3ccd9ec0f02baad85a744b791940b18` |
| `cap-std` | `4.0.3` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `c1ec78e242cfa2cfe276807ac2ecc00315a6c97786977414bcd1c3963b6c91b8` |
| `cfg-if` | `1.0.5` | Runtime library | No | `4e7648175b45a9a48536d676f68d918270699102aa8dab5496df06904c914600` |
| `clap` | `4.6.7` | Runtime library | No | `aa8876b300ab35ba921adea3dfd70157a46249b33f95c9084ae5709785478946` |
| `clap_builder` | `4.6.7` | Runtime library | No | `ec0797fb7aeb1406c84efac526901f7ec3ead2124f946b494e72879d4b54704d` |
| `clap_derive` | `4.6.7` | Proc-macro | **Yes** (macro expansion by rustc) | `f9c751b79415d4e559e3d1fcf128e09e720eb673a06d26cf6f392d37d75b66e0` |
| `clap_lex` | `1.1.1` | Runtime library | No | `1c133bc6a41be0d194c306b5506d15e6feeea7b1d6604bd3f8310dfb2ca96486` |
| `colorchoice` | `1.0.5` | Runtime library | No | `1d07550c9036bf2ae0c684c4297d503f838287c83c53686d05370d0e139ae570` |
| `encoding_rs` | `0.8.35` | Runtime library | No | `75030f3c4f45dafd7586dd6780965a8c7e8e285a5ecb86713e63a79c5b2766f3` |
| `foldhash` | `0.2.0` | Runtime library | No | `77ce24cb58228fbb8aa041425bb1050850ac19177686ea6e0f41a70416f56fdb` |
| `fs-set-times` | `0.20.3` | Runtime library | No | `94e7099f6313ecacbe1256e8ff9d617b75d1bcb16a6fddef94866d225a01a14a` |
| `hashbrown` | `0.17.1` | Runtime library | No | `ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a` |
| `hashlink` | `0.12.2` | Runtime library | No | `a596f1b20ed2cc5ecac41a164aaebc7258057060f06c0cf7a2ba3991ee7990fb` |
| `heck` | `0.5.0` | Runtime library | No | `2304e00983f87ffb38b55b444b5e3b60a884b5d30c0fca7d82fe33449bbe55ea` |
| `io-extras` | `0.19.0` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `20fd6de4ccfcc187e38bc21cfa543cb5a302cb86a8b114eb7f0bf0dc9f8ac00f` |
| `io-lifetimes` | `2.0.4` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `06432fb54d3be7964ecd3649233cddf80db2832f47fec34c01f65b3d9d774983` |
| `io-lifetimes` | `3.0.1` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `2f0fb0570afe1fed943c5c3d4102d5358592d8625fda6a0007fdbe65a92fba96` |
| `ipnet` | `2.12.2` | Runtime library | No | `791930b43c0d5973160d90a8f3894509f2b273430f5c5c73b668636d0287c5c0` |
| `is_terminal_polyfill` | `1.70.2` | Runtime library | No | `a6cb138bb79a146c1bd460005623e142ef0181e3d0219cb493e02f7d08a35695` |
| `itoa` | `1.0.18` | Runtime library | No | `8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682` |
| `linux-raw-sys` | `0.12.1` | Runtime library | No | `32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53` |
| `maybe-owned` | `0.3.4` | Runtime library | No | `4facc753ae494aeb6e3c22f839b158aebd4f9270f55cd3c79906c45476c47ab4` |
| `memchr` | `2.8.3` | Runtime library | No | `cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98` |
| `mergelatch-cli` | `0.1.0` | Workspace binary crate | No (compiled as target) | n/a (workspace source) |
| `mergelatch-core` | `0.1.0` | Workspace library crate | No (compiled as target) | n/a (workspace source) |
| `once_cell` | `1.21.4` | Runtime library | No | `9f7c3e4beb33f85d45ae3e3a1792185706c8e16d043238c593331cc7cd313b50` |
| `proc-macro2` | `1.0.107` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9` |
| `quote` | `1.0.47` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001` |
| `rustix` | `1.1.5` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `891efababe418670775f199f0d233d84843c227a0949a883ce15b37c78d6629d` |
| `rustix-linux-procfs` | `0.1.1` | Runtime library | No | `2fc84bf7e9aa16c4f2c758f27412dc9841341e16aa682d9c7ac308fe3ee12056` |
| `serde` | `1.0.229` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba` |
| `serde_core` | `1.0.229` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48` |
| `serde_derive` | `1.0.229` | Proc-macro | **Yes** (macro expansion by rustc) | `e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348` |
| `serde_json` | `1.0.154` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `e7e9cc8b1b85264074fbcc02a88680c4096b1e47df8f739dceb03bf482f04bd6` |
| `strsim` | `0.11.1` | Runtime library | No | `7da8b5736845d9f2fcb837ea5d9e2628564b3b043a70948a3f0b778838c5fb4f` |
| `syn` | `3.0.9` | Runtime library | No | `d78c8dee4c7bf0e14673097256fed6142ce9d3b85a408189d07482442145823b` |
| `unicode-ident` | `1.0.27` | Runtime library | No | `a2c754d6c33795a1c324727428e5a7dedb5b06195f9890bdbcba760d3e246563` |
| `utf8parse` | `0.2.2` | Runtime library | No | `06abde3611657adf66d383f00b093d7faecc7fa57071cce2578660c9f1010821` |
| `yaml-rust2` | `0.13.0` | Runtime library | No | `57e5b818a27a4cd30884ea380857a5e56f7ec3ba24a3990a3cc0b95af3238e18` |
| `zmij` | `1.0.23` | Build script (`build.rs`) | **Yes** (compiled and run by Cargo) | `29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b` |

*Note on earlier documentation:* Earlier drafts noted 13 build-time crates based on an unpruned `cargo tree` traversal before resolver-3 target filtration. The exact inventory confirms 12 build-script crates (13 package instances due to `io-lifetimes` dual versions) plus 2 proc-macros, totaling 14 distinct crates.

---

### 3. Execution During Installation/Compilation and Network Trust

#### What Executes on the Runner

1. **Toolchain setup (`rustup toolchain install --no-self-update`)**:
   - Downloads channel manifest `channel-rust-1.99.1.toml` and GPG signature from `static.rust-lang.org`.
   - Downloads component tarballs (`rustc`, `cargo`, `rust-std`, `rustfmt`, `clippy`).
   - Unpacks toolchain binaries directly into `${RUSTUP_HOME}/toolchains/1.99.1-x86_64-unknown-linux-gnu/`.
2. **Cargo dependency fetch and compilation (`cargo build --locked --release -p mergelatch-cli`)**:
   - Queries `index.crates.io` index and downloads 45 crate tarballs from `static.crates.io`.
   - Unpacks crate sources into `${CARGO_HOME}/registry/src/`.
   - **Compiles and executes 12 build scripts** (`cap-primitives`, `cap-std`, `io-extras`, `io-lifetimes` 2.0.4, `io-lifetimes` 3.0.1, `proc-macro2`, `quote`, `rustix`, `serde`, `serde_core`, `serde_json`, `zmij`). These run as native binaries with runner user privileges.
   - **Compiles and dynamically links 2 proc-macros** (`clap_derive`, `serde_derive`). `rustc` loads these `.so` libraries into its own memory space and executes macro expansion functions.
   - Links final target binary at `${target_dir}/release/mergelatch`.

#### Network Services Trusted

1. `static.rust-lang.org` / Fastly CDN: Trusted for Rust toolchain manifests and compiler binaries.
2. `crates.io` / `index.crates.io` / CloudFront CDN: Trusted for index metadata and source crate tarballs.
3. `github.com`: Trusted for the initial composite Action checkout at the pinned full commit SHA.

---

### 4. Dependency Advisory Checks

- **Check Date:** 2026-11-15
- **Tool:** `cargo-audit` 0.22.2
- **Advisory Database:** RustSec `advisory-db` (`https://github.com/RustSec/advisory-db.git`, 1,509 security advisories loaded)
- **Scope Scanned:** All 78 crates in `Cargo.lock`
- **Findings:**
  - **1 informational warning:**
    - **Crate:** `rustix` 1.1.5
    - **Advisory ID:** `RUSTSEC-2026-0486` (GHSA-jh2m-fhpj-3vr7)
    - **Title:** *xattr functions mark unwritten bytes as initialized when given a zero-length buffer*
    - **Type:** Informational (unsoundness in `rustix::fs::getxattr`, `lgetxattr`, etc. on zero-length buffer query)
    - **Patched in:** `rustix >= 1.1.6`
  - **Relevance to MergeLatch:** **None (unreachable).** MergeLatch workspace forbids unsafe code (`unsafe_code = "forbid"`). Neither `mergelatch-core` nor `mergelatch-cli` calls any extended-attribute (`xattr`) functions. `rustix` is used strictly for safe directory descriptor operations, metadata stat queries, and symlink verification.
  - **Zero vulnerabilities:** No critical, high, or medium CVEs reported.
- **Limitations of Advisory Checking:**
  - Detects only publicly disclosed and filed RustSec advisories.
  - Cannot detect zero-days, unmaintained dependencies with unfiled flaws, backdoors in upstream compilers, or malicious code inside build scripts matching locked hashes.

---

### 5. Actual Build Timings on GitHub-Hosted Ubuntu Runners

Measurements taken directly from verified GitHub Actions runs on GitHub-hosted `ubuntu-24.04` runners (standard 2-core Azure VMs, image `20261012.334.1`, runner v2.338.0). Timings are extracted from raw API job logs (`gh api /repos/MergeLatch/mergelatch/actions/jobs/<id>/logs`) and represent exact wall-clock durations without fabrication or estimation.

#### Cold Build Measurements (Fresh Runner, No Cached Artifacts)

- **Run 40160502270 (Job 121070889540, step `hostile.build`):**
  - **Total step duration:** **26,003 ms (26.00 s)**
  - `rustup toolchain install --no-self-update`: ~8.69 s (04:04:06.85 to 04:04:15.75)
  - `cargo build --locked --release -p mergelatch-cli`: **17.31 s** (04:04:15.75 to 04:04:32.77)
- **Run 40160323948 (Job 121070318642, step `hostile.build`):**
  - **Total step duration:** **20,396 ms (20.40 s)**
  - `rustup toolchain install --no-self-update`: ~7.73 s (04:01:02.16 to 04:01:09.80)
  - `cargo build --locked --release -p mergelatch-cli`: **12.66 s** (04:01:09.80 to 04:01:22.46)
- **Historical cold run range:** **20.4 s to 27.3 s** across all recorded GitHub runs.

#### Warm Build Measurements (Same Job, Preserved Target Directory)

Subsequent scans in the same job invoke the build step with `CARGO_TARGET_DIR` set to `${RUNNER_TEMP}/mergelatch-cargo-target`.

- **Run 40160502270 (Job 121070889540, steps 2 through 7):**
  - Step `clean.build`: **219 ms** (Cargo incremental check: **0.03 s**)
  - Step `findings.build`: **215 ms** (Cargo incremental check: **0.03 s**)
  - Step `incomplete.build`: **218 ms** (Cargo incremental check: **0.03 s**)
  - Step `head.build`: **216 ms** (Cargo incremental check: **0.03 s**)
  - Step `stale.build`: **218 ms** (Cargo incremental check: **0.03 s**)
  - Step `unverified.build`: **217 ms** (Cargo incremental check: **0.03 s**)
  - Step `unverified_findings.build`: **215 ms** (Cargo incremental check: **0.03 s**)
- **Run 40160323948 (Job 121070318642):**
  - Cargo incremental check: **0.02 s**, total step duration **~200 ms - 210 ms**.
- **Warm build range:** **215 ms to 220 ms** total step overhead; Cargo verifies the up-to-date target in **0.02 s - 0.03 s**.

---

### 6. Offline and Network-Failure Behavior (Fail-Closed Verification)

The Action's execution path was examined under simulated offline or broken network conditions (e.g., DNS failure, timeout, or HTTP 500 from `static.rust-lang.org` or `crates.io`):

1. `action/build.sh` runs with `set -euo pipefail`. If `rustup toolchain install` or `cargo build` fails due to network outage, the script exits immediately with a non-zero exit code.
2. `action/mergelatch_action.py build` reaps the child process and raises `ActionError`, returning exit code 1.
3. In `action.yml`, the build step has `continue-on-error: true`. GitHub Actions marks `steps.build.outcome = 'failure'` and proceeds to `scan`.
4. In `scan()`, `${MLA_STATE_DIR}/binary-path.txt` does not exist because `build.sh` aborted before writing it. `open()` raises `FileNotFoundError`, handled by setting `scan-exit-code.txt` to `127`.
5. In `report()`, `MLA_BUILD_OUTCOME` is evaluated:
   ```python
   if build_outcome is not None and build_outcome != "success":
       result["reason"] = "The scanner could not be built from the Action source."
       return result
   ```
6. `result["status"]` defaults to `"error"`.
7. `report()` logs `::error title=MergeLatch advisory scan::The scan did not produce a trustworthy result. See the job summary.`, writes output `status=error`, and returns exit code 1.
8. **Conclusion:** **The Action fails closed on all build and network failures.** It is impossible for an offline runner or network outage to report `clean` or silently pass. However, any network blip causes consumer PR checks to turn red with status `error`.

---

### 7. Assessment of Shared Cargo Target Directory and F-05 Limitation

- **Location:** In `action/build.sh`, `target_dir="${RUNNER_TEMP}/mergelatch-cargo-target"`.
- **Relationship to F-05:**
  - On GitHub-hosted runners, all steps in a job run under the same user (`runner`, uid 1001) with passwordless `sudo`.
  - `$RUNNER_TEMP` (`/home/runner/work/_temp`) is shared across all steps within the runner job.
  - As confirmed during F-05 testing (PR #24, run 40129287435):
    - A step running prior to the Action (or a persistent background process launched via `nohup setsid`) can pre-populate `${RUNNER_TEMP}/mergelatch-cargo-target/release/mergelatch` with an arbitrary binary.
    - When `cargo build --locked --release` executes, Cargo detects the binary and its fingerprints as already up-to-date and completes in 0.03 s without recompiling, leaving the planted executable intact.
    - The Action then executes this planted executable as the scanner.
  - **Key architectural finding:** Randomizing or privatizing the target directory (e.g. `mkdtemp(prefix="target-", dir=runner_temp)`) does **not** solve F-05. A background process running as `runner` can simply poll `${RUNNER_TEMP}` or `/tmp`, detect the state directory or binary, and replace it before `scan()` executes. Moreover, an earlier step with `sudo` can rewrite `/usr/bin/python3` or `~/.cargo/bin/cargo`.
  - Therefore, **the shared target directory risk is an intrinsic consequence of same-job composition (F-05), not a defect fixable within the Action.**

---

## Phase 2: Design Comparison

| Evaluation Dimension | Approach A: Continue Source Compilation (Current Safeguards) | Approach B: Continue Source Compilation (Additional Safe Protections) | Approach C: Introduce Verified Prebuilt Scanner Binaries |
|---|---|---|---|
| **Trust Boundaries** | Boundary is the immutable GitHub commit SHA pinned by consumer. Scanned repo isolated; build runs in scrubbed env in isolated session. | Same as A, plus target dir randomized per invocation and CI automated audits. | Shifts boundary to GitHub Releases CDN, release signing keys/OIDC, and external binary hosting. |
| **Dependency & Network Exposure** | Contacts `static.rust-lang.org` and `crates.io` on every cold run. 45 registry crates fetched. | If vendored: no `crates.io` traffic, but massive git repo bloat. Still requires `rustup` network. | Single download from GitHub Releases. Fails if GitHub Releases is rate-limited or unreachable. |
| **Build Execution Risks** | 12 build scripts and 2 proc-macros run on runner during build. Bounded by 1,500 s group timeout. | Same as A. Build scripts still execute unless completely rewritten/pruned. | **Zero build scripts execute on runner.** Runner executes opaque precompiled ELF binary. |
| **Artifact Integrity & Provenance** | Native compile directly from git tree pinned by SHA. Provenance is exact git commit. | Same as A. | Requires cryptographic signatures and SLSA provenance. A checksum alone is insufficient. |
| **Binary Compatibility** | **100% native compatibility.** Compiled for runner's exact glibc and CPU features. | 100% native compatibility. | High risk of glibc version mismatches across runner versions. Requires static `musl` toolchain. |
| **Build Time & Resource Costs** | Cold: 20.4 s - 26.0 s; Warm: ~0.22 s. ~75 MB network transfer. | Cold: ~18 s - 22 s; Warm: ~0.22 s. | Cold: **~1 s - 3 s** (download only); Warm: ~0.20 s. ~12 MB network transfer. |
| **Availability & Complexity** | High availability (Rust CDN). Extremely low operational complexity. | Moderate complexity (maintaining vendored tree or cache poisoning defenses). | High operational complexity: release workflows, asset publishing, rate-limit handling, cross-build CI. |
| **Consumer Verification** | Direct: consumer reads open-source repo at the pinned SHA. | Direct: same as A. | Indirect: consumer must verify SLSA attestations or cosign signatures; cannot inspect binary directly. |
| **Maintenance Effort & Free Hosting** | Minimal: standard Cargo lock updates. 100% free hosting. | Moderate: vendoring maintenance. 100% free hosting. | High: release matrix, signing key security, attestation maintenance. Free hosting via GitHub Releases. |

---

### In-Depth Examination of Prebuilt Binaries (Approach C)

#### 1. Why a Checksum Alone Does Not Prove a Binary is Trustworthy

A cryptographic digest (e.g. SHA-256) establishes only **data integrity** relative to the publisher's published value (i.e., "the downloaded bytes match what was hashed"). It does **not** prove:
- That the binary was compiled from the claimed open-source repository commit.
- That the build environment (GitHub runner, container, compiler toolchain) was uncompromised.
- That the publisher or maintainer account releasing the binary was not hijacked.
- That hidden backdoors or compiler trojans were not injected during release artifact compilation.

#### 2. Reproducible-Build Feasibility

For prebuilt binaries to be independently verifiable, builds must be bit-for-bit reproducible across independent machines:
- **Rustc hurdles:** Non-deterministic debug symbols, build path embeddings, incremental compilation artifacts, and host environment variations affect binary hashes.
- **Required mitigations:** Compiling with `--remap-path-prefix`, `RUSTFLAGS="-C link-arg=-Wl,--build-id=none"`, fixed timestamps (`SOURCE_DATE_EPOCH`), and static target linking (`x86_64-unknown-linux-musl`).
- Feasible, but requires substantial ongoing release engineering infrastructure.

#### 3. Cryptographic Digests and Artifact Attestations

To provide trustworthy prebuilt binaries, MergeLatch would require:
- **SLSA Level 3 Provenance / GitHub Artifact Attestations:** Utilizing GitHub's Sigstore integration (`actions/attest-build-provenance`) signed with short-lived OIDC tokens tied to the immutable repository identity, workflow ref, and commit SHA.
- **Verification inside the Action:** The Action helper must verify the attestation before execution. Doing so requires either `gh attestation verify` (requiring `gh` CLI and network access to Sigstore Rekor/Fulcio) or bundling a full cryptographic verification suite into Python, conflicting with the Action's zero-dependency standard-library-only rule.

#### 4. Trusted Release Workflow and Fail-Closed Verification

- Requires dedicated release workflows triggered strictly on annotated, signed tags from maintainers.
- Must run in an isolated environment with `permissions: id-token: write, contents: write, attestations: write`.
- If the binary, digest, or attestation download fails or fails verification, the Action must abort immediately with status `error`.

---

## Phase 3: Recommendation

### Categorized Findings and Status

- **Protections already verified:**
  - Full-SHA commit pinning for immutable Action loading.
  - Python isolated mode (`/usr/bin/python3 -I`) immune to `PYTHON*` and local directory hijacking.
  - Sanitized process environment (`trusted_environment`) purging caller-provided compiler/linker overrides.
  - Locked Cargo dependencies (`--locked`) enforcing 45 cryptographic SHA-256 hashes.
  - Process-group termination preventing orphan build descendants on timeout (F-08).
  - Fail-closed error handling: build failure, network outage, or binary absence results in status `error` and non-zero exit.
  - Workspace-wide `unsafe_code = "forbid"`.
- **Confirmed vulnerabilities or weaknesses:**
  - **F-05 Same-job interference:** A prior step in the same job running as `runner` with `sudo` can tamper with `$RUNNER_TEMP`, `/tmp`, `~/.cargo/bin`, or state files. This is an architectural limitation of GitHub Actions job composition and affects both source compilation and prebuilt binaries equally.
  - **RUSTSEC-2026-0486:** Informational unsoundness warning on `rustix` 1.1.5 xattr functions. Confirmed unreachable in MergeLatch.
- **Accepted risks:**
  - Build-time execution of 12 build scripts (13 packages) and 2 proc-macros from `crates.io` on the runner during cold builds.
  - Dependency on `static.rust-lang.org` and `crates.io` availability during cold builds.
  - Cold build duration of 20 to 26 seconds on fresh runners.
- **Improvements suitable for this stage:**
  - Keep the audit and decision documented in `docs/REVIEW_READINESS.md` and `docs/ACTION.md`.
  - Maintain source build as the approved mechanism.
  - In developer CI, track RustSec advisories while documenting the known `rustix` informational advisory.
- **Changes that should wait for a trusted enforcement architecture:**
  - **Prebuilt binary distribution (Approach C):** Prebuilt binaries reduce build time from ~25 s to ~2 s, but do not eliminate the same-job F-05 interference risk. Furthermore, verifying Sigstore attestations within the standard-library Python helper is non-trivial. Prebuilt binaries should be introduced only when MergeLatch establishes an isolated enforcement architecture (such as a separate merge-gate job, GitHub App, or isolated sidecar environment) where a full SLSA L3 verification pipeline can be enforced.

### Final D-4 Determination

**Recommendation:** **Adopt Approach A (Continue source compilation with current safeguards).**

**Justification:**
1. **Advisory-Only Stage:** MergeLatch is currently an advisory, non-gating check. The primary objective is verifiable correctness, transparent auditability, and zero false-clean bypasses.
2. **Build Time is Acceptable:** Cold builds take ~20–26 seconds, and warm builds take ~0.22 seconds. In typical CI pipelines, this runs in parallel with test suites that take 35–45 seconds. Per project rules: *"Do not change the production Action merely to reduce build time."*
3. **No Solution to F-05:** Prebuilt binaries do not protect against same-job runner compromise (F-05). A malicious prior step can tamper with a downloaded binary just as easily as a compiled binary.
4. **Trust and Simplicity:** Source compilation pinned to a full commit SHA provides direct, inspectable provenance without introducing complex binary signing, OIDC attestation infrastructure, or glibc compatibility risks.
