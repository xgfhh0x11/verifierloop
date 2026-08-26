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

use crate::normalize::RecordParser;
use metrics::core::{
    CoreMetrics, CoverageDelta, Processed, RegSnapshot, RegState, Tnum, VerifierDecision,
};

/// Parser for the differential/verifier-log harness native output.
pub struct VerifierLogParser;

impl RecordParser for VerifierLogParser {
    fn parse(&self, _tool: &str, bytes: &[u8]) -> Vec<CoreMetrics> {
        let text = String::from_utf8_lossy(bytes);
        split_blocks(&text).iter().map(|b| parse_block(b)).collect()
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

/// Parse one program block into a CORE observation.
fn parse_block(block: &str) -> CoreMetrics {
    let mut accept = true;
    let mut in_log = false;
    let mut log: Vec<&str> = Vec::new();

    for line in block.lines() {
        if line.starts_with("RESULT ") {
            accept = line.contains("decision=accept");
        } else if line.starts_with("---LOG---") {
            in_log = true;
        } else if line.starts_with("---END---") {
            in_log = false;
        } else if in_log {
            log.push(line);
        }
    }

    let decision = if accept {
        VerifierDecision::Accept
    } else {
        VerifierDecision::Reject {
            reason: parse_reject_reason(&log),
        }
    };

    CoreMetrics {
        verifier_decision: decision,
        register_evolution: parse_register_evolution(&log),
        processed: parse_processed(&log),
        jit_interp_diff: None,                     // v0: ALWAYS_ON kernel, no interp
        coverage_delta: CoverageDelta::default(),  // exec_n stamped by normalize
        helper_arg_violations: Vec::new(),         // decided at the diff stage
    }
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

/// The verifier's failure line: the last non-empty log line that is neither the
/// `processed ...` summary nor an instruction/state/liveness line. Kept verbatim.
fn parse_reject_reason(log: &[&str]) -> String {
    for line in log.iter().rev() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("processed ") || t.starts_with("func#")
            || t.starts_with("Live regs") || has_digit_head(t)
        {
            continue;
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

fn take_number_token(rest: &str) -> String {
    let mut out = String::new();
    for (i, c) in rest.char_indices() {
        if i == 0 && c == '-' {
            out.push(c);
        } else if c.is_ascii_hexdigit() || c == 'x' || c == 'X' {
            out.push(c);
        } else {
            break;
        }
    }
    out
}

fn field_u64(s: &str, key: &str) -> Option<u64> {
    let idx = s.find(key)? + key.len();
    parse_uint(&take_number_token(&s[idx..]))
}

fn field_i64(s: &str, key: &str) -> Option<i64> {
    let idx = s.find(key)? + key.len();
    let (_, i) = parse_const_int(&take_number_token(&s[idx..]))?;
    Some(i)
}

/// Parse the leading unsigned integer immediately after `key` in `s`.
fn num_after(s: &str, key: &str) -> Option<u64> {
    let idx = s.find(key)? + key.len();
    let digits: String = s[idx..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
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
        VerifierLogParser.parse("diffharness", SAMPLE.as_bytes())
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
}
