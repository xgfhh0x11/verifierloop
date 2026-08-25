//! The fuzzer-driver abstraction.
//!
//! The loop advances a period by **exec count** and, at the boundary, ingests the
//! native output the fuzzers wrote. A [`FuzzDriver`] hides *how* execs are produced
//! so the loop control flow is testable without a real VM/syzkaller.
//!
//! The real driver (VM-backed: `vmctl` + syzkaller + differential harness) is not
//! implemented yet — see the TODO on [`FuzzDriver`]. [`MockDriver`] simulates
//! progress + native output for tests and the `period_spine` example.

use pipeline::ingest::Source;
use std::path::PathBuf;

/// Errors from a fuzzer driver.
#[derive(Debug)]
pub enum DriverError {
    /// Filesystem I/O failure (e.g. writing/locating native output).
    Io(std::io::Error),
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriverError::Io(e) => write!(f, "driver i/o error: {e}"),
        }
    }
}

impl std::error::Error for DriverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DriverError::Io(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for DriverError {
    fn from(e: std::io::Error) -> Self {
        DriverError::Io(e)
    }
}

/// Drives the fuzzers and reports progress by cumulative exec count.
///
/// TODO(driver): implement a real VM-backed driver — boot a disposable bpf-next
/// VM via `vmctl`, launch syzkaller + the differential harness, read the KCOV/exec
/// counter, and point `sources()` at each tool's DEFAULT-mode native output dir.
pub trait FuzzDriver {
    /// Total fuzzing execs observed so far (cumulative, monotonically increasing).
    /// This is the ONLY quantity that advances a period — never wall-clock time.
    fn exec_count(&self) -> u64;

    /// Advance the fuzzers and return the new cumulative exec count. Implementations
    /// MUST make progress (strictly increase the count) so a period can terminate.
    fn pump(&mut self) -> Result<u64, DriverError>;

    /// Where each tool has written its DEFAULT-mode native output, for `ingest` to
    /// collect UNCHANGED at the harvest point.
    fn sources(&self) -> Vec<Source>;
}

/// A deterministic in-process driver: each `pump` bumps the exec count by a fixed
/// step and (re)writes a fake native-output file per tool. For tests/examples only.
#[derive(Debug)]
pub struct MockDriver {
    exec: u64,
    per_pump: u64,
    out_root: PathBuf,
    tools: Vec<String>,
}

impl MockDriver {
    /// `out_root` is where fake native output is written (one sub-dir per tool);
    /// each `pump` adds `per_pump` execs.
    pub fn new(out_root: impl Into<PathBuf>, tools: &[&str], per_pump: u64) -> Self {
        Self {
            exec: 0,
            per_pump: per_pump.max(1),
            out_root: out_root.into(),
            tools: tools.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl FuzzDriver for MockDriver {
    fn exec_count(&self) -> u64 {
        self.exec
    }

    fn pump(&mut self) -> Result<u64, DriverError> {
        self.exec += self.per_pump;
        // Simulate each tool appending to its native output (opaque to the loop).
        for tool in &self.tools {
            let dir = self.out_root.join(tool);
            std::fs::create_dir_all(&dir)?;
            std::fs::write(
                dir.join("log.txt"),
                format!("mock {tool} native output @ exec={}\n", self.exec),
            )?;
        }
        Ok(self.exec)
    }

    fn sources(&self) -> Vec<Source> {
        self.tools
            .iter()
            .map(|t| Source::new(t, self.out_root.join(t)))
            .collect()
    }
}
