//! Real per-tool parser #2 — the differential/verifier-log harness output.
//!
//! Interprets the native output of `harness/diffharness.c` into [`CoreMetrics`].
//! This is the producer of the verifier-SEMANTIC CORE fields (decision +
//! register-state evolution) that syzkaller does not emit (see devlog 0010/0011).
//!
//! Native format (one block per program):
//! ```text
//! ===PROG <name> type=<t> ===
//! RESULT decision=<accept|reject> fd=<n> errno=<e> load_ns=<n>
//! ---LOG---
//! <verbatim kernel verifier log>
//! ---END---
//! ```
//!
//! v0 scope: `decision`, reject `reason` (verbatim), `register_evolution`,
//! `processed`. `jit_interp_diff` is `None` — the primary kernel is
//! `BPF_JIT_ALWAYS_ON` so there is no interpreter to diff against (deferred to a
//! cross-kernel mode). Helper `arg_type` violations are decided at the `diff`
//! stage, not here.
//!
//! UNCHANGED-AT-SOURCE: this reads bytes and never mutates them; shaping into the
//! schema is interpretation, done here in `normalize` and nowhere earlier.

use crate::normalize::{ParseOutput, ParsedRecord, RecordParser, UnparsedBlock};
use metrics::core::{
    CoreMetrics, CoverageDelta, HelperArgObservation, Processed, RegSnapshot, RegState, Tnum,
    VerifierDecision,
};

/// Parser for the differential/verifier-log harness native output.
pub struct VerifierLogParser;

impl RecordParser for VerifierLogParser {
    fn parse(&self, _tool: &str, bytes: &[u8]) -> ParseOutput {
        let text = String::from_utf8_lossy(bytes);
        let mut records = Vec::new();
        let mut unparsed = Vec::new();
        for b in split_blocks(&text) {
            match classify_block(&b) {
                Ok(pr) => records.push(pr),
                Err(ub) => unparsed.push(ub),
            }
        }
        ParseOutput { records, unparsed }
    }
}

/// Split the harness output into per-program blocks (each starts at `===PROG `).
fn split_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        if line.starts_with("===PROG ") {
            if let Some(b) = cur.take() {
                blocks.push(b);
            }
            cur = Some(String::new());
        }
        if let Some(b) = cur.as_mut() {
            b.push_str(line);
            b.push('\n');
        }
    }
    if let Some(b) = cur.take() {
        blocks.push(b);
    }
    blocks
}

/// Classify one native block: either a trustworthy record, or an [`UnparsedBlock`]
/// kept in a SEPARATE bucket. UNPARSED POLICY — a block the parser cannot trust
/// (no verifier decision, or a non-verifier RESULT) is NEVER turned into a
/// default-filled record (which could masquerade as a clean accept) and NEVER
/// treated as an anomaly; it is surfaced as a parser blind-spot. Recognized blocks
/// may still carry per-record `notes` for partially-unrecognized content.
fn classify_block(block: &str) -> Result<ParsedRecord, UnparsedBlock> {
    let label = block_label(block);
    let mut result_line: Option<&str> = None;
    let mut in_log = false;
    let mut log: Vec<&str> = Vec::new();

    for line in block.lines() {
        if line.starts_with("RESULT ") {
            result_line = Some(line);
        } else if line.starts_with("---LOG---") {
            in_log = true;
        } else if line.starts_with("---END---") {
            in_log = false;
        } else if in_log {
            log.push(line);
        }
    }

    // Block-level unparsed: no trustworthy verifier decision -> do NOT invent a record.
    let result = match result_line {
        Some(r) => r,
        None => {
            return Err(UnparsedBlock {
                label,
                reason: "no RESULT line — decision unknown".to_string(),
            })
        }
    };
    let decision = if result.contains("decision=accept") {
        VerifierDecision::Accept
    } else if result.contains("decision=reject") {
        VerifierDecision::Reject {
            reason: parse_reject_reason(&log),
        }
    } else {
        // e.g. `decision=error` (harness map-create failure) — not a verifier obs.
        return Err(UnparsedBlock {
            label,
            reason: format!("non-verifier RESULT: {}", result.trim()),
        });
    };

    let core = CoreMetrics {
        verifier_decision: decision,
        register_evolution: parse_register_evolution(&log),
        processed: parse_processed(&log),
        jit_interp_diff: None,                    // v0: ALWAYS_ON kernel, no interp
        coverage_delta: CoverageDelta::default(), // exec_n stamped by normalize
        helper_arg_observations: parse_helper_calls(&log),
        helper_arg_violations: Vec::new(),        // legacy synthetic path
    };

    // Record-level parse notes: partial-parse caveats (lower confidence, NOT anomalies).
    let mut notes = Vec::new();
    if !log.iter().any(|l| l.trim_start().starts_with("processed ")) {
        notes.push("missing 'processed' counters".to_string());
    }
    for fam in unrecognized_reg_families(&core) {
        notes.push(format!("unrecognized reg-type form: {fam}"));
    }

    Ok(ParsedRecord { core, notes })
}

/// The `===PROG <name> ...` label of a block (for triage), or "block".
fn block_label(block: &str) -> String {
    block
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("===PROG "))
        .map(|r| r.split_whitespace().next().unwrap_or("?").to_string())
        .unwrap_or_else(|| "block".to_string())
}

/// Reg-type families the parser does NOT recognize (novel forms a high-volume
/// period might surface). Flagged as a note so a blind-spot cannot pass as clean.
fn unrecognized_reg_families(core: &CoreMetrics) -> Vec<String> {
    const KNOWN: &[&str] = &[
        "scalar", "map_ptr", "map_value", "map_value_or_null", "ctx", "fp", "pkt",
        "pkt_meta", "pkt_end", "flow_keys", "sock", "sock_common", "tcp_sock",
        "func", "stack", "ringbuf_mem", "buf", "mem", "btf_id", "trusted_ptr",
    ];
    let mut out = std::collections::BTreeSet::new();
    for snap in &core.register_evolution {
        for r in &snap.regs {
            let fam = if r.reg_type.starts_with("fp") {
                "fp"
            } else {
                r.reg_type.as_str()
            };
            if !KNOWN.contains(&fam) {
                out.insert(fam.to_string());
            }
        }
    }
    out.into_iter().collect()
}

/// Does `t` begin with a `<digits>:` head (an instruction / state / liveness line)?
fn has_digit_head(t: &str) -> bool {
    match t.find(':') {
        Some(c) => {
            let head = &t[..c];
            !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// The verifier's failure line. Scans forward for the FIRST un-indented, non-empty
/// line that appears AFTER the per-insn state section and is not a state/summary
/// line. On both the host and bpf-next logs this is the concise verifier token
/// (e.g. `R0 !read_ok`) — stable across bpf-next's richer multi-line diagnostic
/// (`Verification failed: ...`, `Reason:`, `Suggestion:`) that follows it, and
/// past its pre-analysis preamble (`func#`, `topo_order`, `subprog#`,
/// `stack use/def`). Indented lines are preamble/detail and are skipped. Verbatim.
fn parse_reject_reason(log: &[&str]) -> String {
    let mut seen_state = false;
    for line in log {
        if line.starts_with(' ') {
            continue; // indented: disasm / liveness / diagnostic detail
        }
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if has_digit_head(t) {
            seen_state = true; // an un-indented "N: ..." state/insn line
            continue;
        }
        if !seen_state || t.starts_with("processed ") {
            continue; // still in the analysis preamble, or the summary line
        }
        return t.to_string();
    }
    "unknown".to_string()
}

/// `processed N insns ... total_states T ...` -> insn_processed = N, states = T.
fn parse_processed(log: &[&str]) -> Processed {
    for line in log {
        let t = line.trim_start();
        if t.starts_with("processed ") {
            return Processed {
                insn_processed: num_after(t, "processed ").unwrap_or(0),
                states_processed: num_after(t, "total_states ").unwrap_or(0),
            };
        }
    }
    Processed::default()
}

/// Build the per-insn register-state snapshots from the verifier log.
fn parse_register_evolution(log: &[&str]) -> Vec<RegSnapshot> {
    let mut snaps = Vec::new();
    for line in log {
        // Liveness lines are indented ("      0: ..."); skip them.
        if line.starts_with(' ') {
            continue;
        }
        let t = line.trim();
        let colon = match t.find(':') {
            Some(c) => c,
            None => continue,
        };
        let head = &t[..colon];
        if head.is_empty() || !head.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let insn_idx: u32 = match head.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let rest = t[colon + 1..].trim_start();

        // (a) full-state line: "R1=ctx() R10=fp0"  (starts with a reg token)
        // (b) instruction line: "(b7) r0 = 0 ; R0=0"  (state after ';')
        let state = if looks_like_reg_token_start(rest) {
            Some(rest)
        } else {
            rest.find(';').map(|s| rest[s + 1..].trim())
        };

        if let Some(ss) = state {
            let regs = parse_reg_tokens(ss);
            if !regs.is_empty() {
                snaps.push(RegSnapshot { insn_idx, regs });
            }
        }
    }
    snaps
}

/// True if `s` begins with a `R<digits>=` token.
fn looks_like_reg_token_start(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b[0] != b'R' {
        return false;
    }
    let mut i = 1;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    i > 1 && i < b.len() && b[i] == b'='
}

/// Split a state string into `R<k>=<expr>` tokens. Robust to spaces inside a
/// value's parens (e.g. `var_off=(0x0; 0xff)`): tokens break only at a boundary
/// where a space is followed by `R<digits>=`.
fn split_reg_tokens(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let n = b.len();
    let mut starts = Vec::new();
    let mut i = 0;
    while i < n {
        if b[i] == b'R' && (i == 0 || b[i - 1] == b' ') {
            let mut j = i + 1;
            while j < n && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 && j < n && b[j] == b'=' {
                starts.push(i);
            }
        }
        i += 1;
    }
    let mut out = Vec::new();
    for k in 0..starts.len() {
        let a = starts[k];
        let e = if k + 1 < starts.len() { starts[k + 1] } else { n };
        out.push(s[a..e].trim());
    }
    out
}

fn parse_reg_tokens(s: &str) -> Vec<RegState> {
    split_reg_tokens(s)
        .into_iter()
        .filter_map(parse_reg_token)
        .collect()
}

/// Parse one `R<k>=<expr>` token into a RegState.
fn parse_reg_token(tok: &str) -> Option<RegState> {
    let eq = tok.find('=')?;
    let regpart = &tok[..eq];
    if !regpart.starts_with('R') {
        return None;
    }
    let reg: u8 = regpart[1..].parse().ok()?;
    Some(build_regstate(reg, tok[eq + 1..].trim()))
}

/// Interpret a register value expression into a RegState.
///
/// Never fabricates a malformed tnum: a const gets `mask=0`, an unknown scalar
/// gets `value=0` (so `value & mask == 0` always holds and the `diff` stage's
/// tnum invariant is not tripped by parsing).
fn build_regstate(reg: u8, expr: &str) -> RegState {
    // (a) const scalar: a bare integer (decimal/hex, maybe negative).
    if let Some((u, i)) = parse_const_int(expr) {
        return RegState {
            reg,
            reg_type: "scalar".to_string(),
            tnum: Tnum { value: u, mask: 0 },
            umin: u,
            umax: u,
            smin: i,
            smax: i,
        };
    }
    // (b) scalar(...) with optional bounds / var_off.
    if expr == "scalar" || expr.starts_with("scalar(") {
        let (value, mask) = parse_var_off(expr).unwrap_or((0, u64::MAX));
        return RegState {
            reg,
            reg_type: "scalar".to_string(),
            tnum: Tnum { value, mask },
            umin: field_u64(expr, "umin=").unwrap_or(0),
            umax: field_u64(expr, "umax=").unwrap_or(u64::MAX),
            smin: field_i64(expr, "smin=").unwrap_or(i64::MIN),
            smax: field_i64(expr, "smax=").unwrap_or(i64::MAX),
        };
    }
    // (c) pointer / ctx / fp / map_value / etc. — verbatim type prefix.
    let ty = expr.split(['(', ' ']).next().unwrap_or(expr);
    RegState {
        reg,
        reg_type: if ty.is_empty() { expr.to_string() } else { ty.to_string() },
        tnum: Tnum::default(),
        umin: 0,
        umax: 0,
        smin: 0,
        smax: 0,
    }
}

/// Parse a bare integer const: `13`, `-1`, `0xff`, `-0x10`. Returns (u64 bits, i64).
fn parse_const_int(s: &str) -> Option<(u64, i64)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let v = u64::from_str_radix(h, 16).ok()?;
        return Some((v, v as i64));
    }
    if let Some(h) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        let v = i64::from_str_radix(h, 16).ok().map(|x| -x)?;
        return Some((v as u64, v));
    }
    if let Ok(v) = s.parse::<i64>() {
        return Some((v as u64, v));
    }
    if let Ok(v) = s.parse::<u64>() {
        return Some((v, v as i64));
    }
    None
}

/// Parse `var_off=(<value>; <mask>)` -> (value, mask).
fn parse_var_off(s: &str) -> Option<(u64, u64)> {
    let start = s.find("var_off=(")? + "var_off=(".len();
    let rest = &s[start..];
    let close = rest.find(')')?;
    let mut parts = rest[..close].split(';');
    let v = parse_uint(parts.next()?.trim())?;
    let m = parse_uint(parts.next()?.trim())?;
    Some((v, m))
}

fn parse_uint(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Return the numeric token a `key` equals, skipping any chained `word=`
/// assignments the verifier prints for shared values (e.g. `smax=umax=255` or
/// `smax=umax=smax32=umax32=255` — all equal the trailing number).
fn value_after_key<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let b = s.as_bytes();
    let mut pos = s.find(key)? + key.len();
    loop {
        if pos < b.len() && (b[pos].is_ascii_digit() || b[pos] == b'-') {
            let start = pos;
            let mut end = pos;
            if b[end] == b'-' {
                end += 1;
            }
            while end < b.len()
                && (b[end].is_ascii_hexdigit() || b[end] == b'x' || b[end] == b'X')
            {
                end += 1;
            }
            return Some(&s[start..end]);
        }
        // Skip an intervening `word=` chain (`umax=` in `smax=umax=255`).
        let start = pos;
        while pos < b.len() && (b[pos].is_ascii_alphanumeric() || b[pos] == b'_') {
            pos += 1;
        }
        if pos > start && pos < b.len() && b[pos] == b'=' {
            pos += 1;
            continue;
        }
        return None;
    }
}

fn field_u64(s: &str, key: &str) -> Option<u64> {
    parse_uint(value_after_key(s, key)?)
}

fn field_i64(s: &str, key: &str) -> Option<i64> {
    let (_, i) = parse_const_int(value_after_key(s, key)?)?;
    Some(i)
}

/// Parse the leading unsigned integer immediately after `key` in `s`.
fn num_after(s: &str, key: &str) -> Option<u64> {
    let idx = s.find(key)? + key.len();
    let digits: String = s[idx..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Normalize a verifier reg-type to a coarse FAMILY for helper-arg comparison:
/// stack pointers (`fp-4`, `fp0`) collapse to `fp`; everything else (already
/// stripped of its `(...)` detail by `build_regstate`) passes through.
fn reg_family(reg_type: &str) -> String {
    if reg_type.starts_with("fp") {
        "fp".to_string()
    } else {
        reg_type.to_string()
    }
}

/// Extract helper-call argument OBSERVATIONS from the verifier log: accumulate
/// each register's reg-type family across the (un-indented) state trace, and at a
/// `(85) call <helper>#<id>` site record the observed family of arg registers
/// R1..R5 that have a tracked state (arg N = R(N+1)). The EXPECTED arg_type is not
/// decided here — that is ground truth's job at the `diff` stage.
fn parse_helper_calls(log: &[&str]) -> Vec<HelperArgObservation> {
    use std::collections::BTreeMap;
    let mut current: BTreeMap<u8, String> = BTreeMap::new();
    let mut obs = Vec::new();

    for line in log {
        if line.starts_with(' ') {
            continue; // indented preamble / liveness / precision annotations
        }
        let t = line.trim();
        let colon = match t.find(':') {
            Some(c) => c,
            None => continue,
        };
        let head = &t[..colon];
        if head.is_empty() || !head.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let rest = t[colon + 1..].trim_start();

        // Full-state line ("R1=ctx() R10=fp0"): refresh every listed reg.
        if looks_like_reg_token_start(rest) {
            for r in parse_reg_tokens(rest) {
                current.insert(r.reg, reg_family(&r.reg_type));
            }
            continue;
        }

        // Instruction line: "(op) disasm [; <state deltas>]".
        let (disasm, state) = match rest.find(';') {
            Some(i) => (rest[..i].trim(), rest[i + 1..].trim()),
            None => (rest, ""),
        };

        // A call site: record args from the state accumulated BEFORE this insn.
        if let Some(helper) = disasm.strip_prefix("(85) call ").map(|h| {
            h.split(['#', ' ']).next().unwrap_or(h).to_string()
        }) {
            for reg in 1u8..=5 {
                if let Some(fam) = current.get(&reg) {
                    obs.push(HelperArgObservation {
                        helper: helper.clone(),
                        arg_index: reg - 1,
                        observed: fam.clone(),
                    });
                }
            }
        }

        // Apply this line's state deltas (e.g. the call's `; R0=map_value`).
        if !state.is_empty() {
            for r in parse_reg_tokens(state) {
                current.insert(r.reg, reg_family(&r.reg_type));
            }
        }
    }
    obs
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real diffharness output (host kernel 6.18), trimmed to the three blocks.
    // Mirrors harness/samples/host-6.18-sample.txt — the parser's known-good input.
    const SAMPLE: &str = "\
===PROG return0 type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=68595
---LOG---
func#0 @0
Live regs before insn:
      0: .......... (b7) r0 = 0
      1: 0......... (95) exit
0: R1=ctx() R10=fp0
0: (b7) r0 = 0                        ; R0=0
1: (95) exit
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0

---END---
===PROG alu_state type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=30275
---LOG---
0: R1=ctx() R10=fp0
0: (b7) r0 = 1                        ; R0=1
1: (67) r0 <<= 3                      ; R0=8
2: (57) r0 &= 255                     ; R0=8
3: (07) r0 += 5                       ; R0=13
4: (95) exit
processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
---END---
===PROG uninit_r0 type=socket_filter ===
RESULT decision=reject fd=-1 errno=13 load_ns=14182
---LOG---
0: R1=ctx() R10=fp0
0: (95) exit
R0 !read_ok
processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
---END---
";

    fn parse_all() -> Vec<CoreMetrics> {
        VerifierLogParser
            .parse("diffharness", SAMPLE.as_bytes())
            .records
            .into_iter()
            .map(|r| r.core)
            .collect()
    }

    fn reg_in(snaps: &[RegSnapshot], reg: u8) -> Option<RegState> {
        snaps
            .iter()
            .flat_map(|s| s.regs.iter())
            .find(|r| r.reg == reg)
            .cloned()
    }

    #[test]
    fn parses_three_programs() {
        assert_eq!(parse_all().len(), 3);
    }

    #[test]
    fn return0_is_accept_with_counters_and_const_r0() {
        let c = &parse_all()[0];
        assert_eq!(c.verifier_decision, VerifierDecision::Accept);
        assert_eq!(c.processed.insn_processed, 2);
        assert_eq!(c.processed.states_processed, 0);
        assert!(c.jit_interp_diff.is_none());
        // R0=0 const scalar: tnum well-formed (mask 0), bounds pinned to 0.
        let r0 = reg_in(&c.register_evolution, 0).expect("R0 present");
        assert_eq!(r0.reg_type, "scalar");
        assert_eq!(r0.tnum, Tnum { value: 0, mask: 0 });
        assert_eq!((r0.umin, r0.umax, r0.smin, r0.smax), (0, 0, 0, 0));
        // Non-scalar ctx/fp captured verbatim as reg types.
        let r1 = reg_in(&c.register_evolution, 1).expect("R1 present");
        assert_eq!(r1.reg_type, "ctx");
        let r10 = reg_in(&c.register_evolution, 10).expect("R10 present");
        assert_eq!(r10.reg_type, "fp0");
    }

    #[test]
    fn alu_state_tracks_r0_evolution() {
        let c = &parse_all()[1];
        assert_eq!(c.verifier_decision, VerifierDecision::Accept);
        assert_eq!(c.processed.insn_processed, 5);
        // The R0 values seen across the program, in order.
        let r0_vals: Vec<u64> = c
            .register_evolution
            .iter()
            .flat_map(|s| s.regs.iter())
            .filter(|r| r.reg == 0)
            .map(|r| r.tnum.value)
            .collect();
        assert_eq!(r0_vals, vec![1, 8, 8, 13]);
        // Every parsed tnum stays well-formed (value & mask == 0).
        for snap in &c.register_evolution {
            for r in &snap.regs {
                assert_eq!(r.tnum.value & r.tnum.mask, 0, "malformed tnum from parser");
            }
        }
    }

    #[test]
    fn uninit_r0_is_reject_with_verbatim_reason() {
        let c = &parse_all()[2];
        assert_eq!(
            c.verifier_decision,
            VerifierDecision::Reject {
                reason: "R0 !read_ok".to_string()
            }
        );
        assert_eq!(c.processed.insn_processed, 1);
    }

    #[test]
    fn tokenizer_handles_spaces_inside_var_off() {
        // Synthetic full-scalar form (not in the host sample) — best-effort path.
        let toks = split_reg_tokens("R0=scalar(umin=0,umax=255,var_off=(0x0; 0xff)) R6=ctx()");
        assert_eq!(toks, vec!["R0=scalar(umin=0,umax=255,var_off=(0x0; 0xff))", "R6=ctx()"]);
        let r0 = parse_reg_token(toks[0]).unwrap();
        assert_eq!(r0.reg_type, "scalar");
        assert_eq!(r0.tnum, Tnum { value: 0, mask: 0xff });
        assert_eq!((r0.umin, r0.umax), (0, 255));
        assert_eq!(r0.tnum.value & r0.tnum.mask, 0);
    }

    // Authoritative in-VM capture from the self-built bpf-next kernel: a richer log
    // (topo_order/subprog/stack use-def preamble + multi-line reject diagnostic).
    const BPF_NEXT_SAMPLE: &str = include_str!("../../../harness/samples/bpf-next-sample.txt");

    #[test]
    fn parses_bpf_next_richer_format() {
        let recs: Vec<CoreMetrics> = VerifierLogParser
            .parse("diffharness", BPF_NEXT_SAMPLE.as_bytes())
            .records
            .into_iter()
            .map(|r| r.core)
            .collect();
        assert_eq!(recs.len(), 7, "seven blocks (3 basic + 3 ranged + 1 helper call)");

        // Accept + counters survive the extra preamble.
        assert_eq!(recs[0].verifier_decision, VerifierDecision::Accept);
        assert_eq!(recs[0].processed.insn_processed, 2);

        // The pre-analysis disasm (indented) must NOT create bogus snapshots — the
        // R0 evolution is still exactly the real state line values.
        let r0_vals: Vec<u64> = recs[1]
            .register_evolution
            .iter()
            .flat_map(|s| s.regs.iter())
            .filter(|r| r.reg == 0)
            .map(|r| r.tnum.value)
            .collect();
        assert_eq!(r0_vals, vec![1, 8, 8, 13]);

        // Reject reason is the concise token, NOT the trailing "Suggestion:" line.
        assert_eq!(
            recs[2].verifier_decision,
            VerifierDecision::Reject {
                reason: "R0 !read_ok".to_string()
            }
        );

        // FULL scalar(...) form on REAL data — the chained-value fields
        // (`smax=umax=smax32=umax32=255`) and var_off must parse correctly.
        // ranged_and (rec 3): `r0 &= 255` -> var_off=(0x0; 0xff), bounds 0..255.
        let masked = recs[3]
            .register_evolution
            .iter()
            .flat_map(|s| s.regs.iter())
            .find(|r| r.reg == 0 && r.tnum.mask == 0xff)
            .expect("masked R0 scalar present");
        assert_eq!(masked.reg_type, "scalar");
        assert_eq!(masked.tnum, Tnum { value: 0, mask: 0xff });
        assert_eq!((masked.umin, masked.umax), (0, 255));
        assert_eq!((masked.smin, masked.smax), (0, 255));

        // shift_unknown (rec 4): `r0 <<= 8` -> var_off=(0x0; 0xffffffff00).
        let shifted = recs[4]
            .register_evolution
            .iter()
            .flat_map(|s| s.regs.iter())
            .find(|r| r.reg == 0 && r.tnum.mask == 0xffffffff00)
            .expect("shifted R0 scalar present");
        assert_eq!(shifted.tnum.value, 0);

        // map_lookup (rec 6): the helper-call parser OBSERVES the arg reg-type
        // families from the real call site — no expected/decision here.
        let mlk = &recs[6].helper_arg_observations;
        assert!(
            mlk.iter().any(|o| o.helper == "bpf_map_lookup_elem" && o.arg_index == 0 && o.observed == "map_ptr"),
            "arg0 observed as map_ptr; got {mlk:?}"
        );
        assert!(
            mlk.iter().any(|o| o.helper == "bpf_map_lookup_elem" && o.arg_index == 1 && o.observed == "fp"),
            "arg1 observed as fp (PTR_TO_STACK); got {mlk:?}"
        );
        // The scalar-only programs record NO helper observations.
        assert!(recs[3].helper_arg_observations.is_empty());

        // Every parsed tnum stays well-formed (value & mask == 0) across all recs —
        // the parser must never manufacture an inconsistency that diff would flag.
        for rec in &recs {
            for snap in &rec.register_evolution {
                for r in &snap.regs {
                    assert_eq!(r.tnum.value & r.tnum.mask, 0, "malformed tnum from parser");
                }
            }
        }
    }
}
