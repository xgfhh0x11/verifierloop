//! COMPOSITION GENERATOR (devlog 0054, `--gen-comp`) — the second half of the fourth
//! pivot, and the first family whose shapes nobody named.
//!
//! Switching surface (0053) addressed one axis: mature code versus fresh. It did not
//! address the other. Every family before this one, that one included, produces shapes
//! whose bug class can be NAMED, so "clean" has only ever meant "clean on the shapes I
//! thought to write". This generator composes the pieces built across 0043-0053 at
//! random — link forms, spills, ALU shaping, branch narrowing, bounded loops, dynptr
//! slices — with the oracles held fixed.
//!
//! THE HARD PART IS VALIDITY, NOT THE ORACLE. A randomly concatenated program is almost
//! always rejected, and a rejected program never reaches the runtime oracles: a
//! denominator-zero trap one layer up from the ones 0041-0050 kept finding. The fix is to
//! treat a program as a walk over a typed CONTEXT rather than a byte string — every piece
//! declares what it REQUIRES of the live state and what it PROVIDES, and only pieces
//! whose requirements currently hold are ever offered.
//!
//! THE CONTEXT CARRIES MORE THAN REGISTER TYPES, and dynptr is why: its interface is the
//! richest of the pieces. It consumes a 16-byte STACK_DYNPTR slot pair the verifier tracks
//! by id, and yields a PTR_TO_MEM whose size is a constant the caller chose — plus an
//! OFFSET into the map value that the slice's base corresponds to, which is 0053's
//! coordinate translation generalised so the store's declared offset is always in the
//! coordinates the sentinel readback uses.
//!
//! THE VALIDITY RESULT IS THE HEADLINE, and it is what makes the zero interpretable:
//! nineteen of the forty-eight programs are rejected, and ALL NINETEEN are rejected on
//! BOUNDS — "Add or adjust a bounds check that proves offset + access_size stays within
//! the object". ZERO are rejected structurally: no uninitialised register, no unreachable
//! instruction, no invalid instruction. Every program the generator emits is
//! well-formed, and the only thing that decides its verdict is the semantic question the
//! oracle already asks.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use std::collections::BTreeSet;

const COMP: &str = include_str!("fixtures/volume/gen-comp-192.log");
const PROGRAMS: usize = 192;
const ACCEPTED: usize = 150;

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-comp-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("c.log");
    std::fs::write(&src, text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("c", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (norm, out)
}

fn recipes() -> Vec<String> {
    COMP.lines()
        .filter(|l| l.starts_with("COMP "))
        .filter_map(|l| l.split_whitespace().find_map(|t| t.strip_prefix("recipe=")))
        .map(str::to_string)
        .collect()
}

/// THE VALIDITY METRIC, and the reviewer's warning answered with a measurement. Raw accept
/// rate is the wrong number: a rejection is a legitimate verdict. The right question is
/// whether rejections are SEMANTIC (the store is genuinely out of bounds) or STRUCTURAL
/// (the generator emitted something malformed). Structural rejections would mean the walk
/// is producing garbage the oracle can never see.
/// Every distinct rejection reason in the corpus, as the verifier phrased it.
fn rejection_reasons() -> Vec<String> {
    let mut out = Vec::new();
    for block in COMP.split("===PROG ").skip(1) {
        if !block.contains("RESULT decision=reject") {
            continue;
        }
        let log = match block.split_once("---LOG---") {
            Some((_, l)) => l,
            None => continue,
        };
        if let Some(line) = log.lines().find(|l| {
            l.starts_with('R') && l.contains("unbounded memory access")
                || l.starts_with("invalid access to map value")
                || l.starts_with("math between")
                || l.starts_with("Initialize R")
                || l.contains("unreachable instruction")
                || l.contains("!read_ok")
                || l.starts_with("invalid bpf_ld")
                || l.contains("unknown opcode")
                || l.contains("jump out of range")
        }) {
            out.push(line.split(',').next().unwrap_or(line).trim().to_string());
        }
    }
    out
}

/// THE VALIDITY METRIC, and the reviewer's warning answered with a measurement. Raw accept
/// rate is the wrong number: a rejection is a legitimate verdict. The right question is
/// whether rejections are SEMANTIC (the store is genuinely out of bounds) or STRUCTURAL
/// (the generator emitted something malformed). Structural rejections would mean the walk
/// is producing garbage the oracle can never see.
///
/// This is written as an ALLOWLIST rather than a pattern for "structural", because the
/// first version used a loose `invalid ` match and counted "invalid access to map value"
/// — a BOUNDS error — as structural. A metric that cries wolf is worse than none. Any
/// rejection reason not on this list is unclassified and must be triaged before the
/// corpus is trusted.
#[test]
fn every_rejection_is_semantic_and_none_is_structural() {
    let semantic = [
        "unbounded memory access",             // the offset register has no proven bound
        "invalid access to map value",         // the constant offset is out of range
        "math between",                        // pointer arithmetic with an unbounded reg
    ];
    let structural = ["Initialize R", "!read_ok", "unreachable", "unknown opcode",
                      "invalid bpf_ld", "jump out of range"];
    let reasons = rejection_reasons();
    let rejects = COMP.matches("RESULT decision=reject").count();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for r in &reasons {
        seen.insert(r.clone());
    }
    eprintln!("COMP rejects={rejects} classified={} distinct={:?}", reasons.len(), seen);
    assert_eq!(
        reasons.len(), rejects,
        "every rejection must be classifiable — an unrecognised reason means a shape the \
         generator produces that nobody has looked at"
    );
    for r in &seen {
        assert!(
            semantic.iter().any(|p| r.contains(p)),
            "unclassified rejection reason, triage before trusting the corpus: {r}"
        );
        assert!(
            !structural.iter().any(|p| r.contains(p)),
            "a structural rejection means the typed walk emitted something malformed, and \
             a malformed program teaches the oracles nothing: {r}"
        );
    }
}

/// The sub-register axis has to be LIVE in the corpus, not merely present as a piece. The
/// first widened run scored reg32_checked = 0 while alu32 was its most-used piece: the
/// initial scalars came from 32-bit loads, which zero-extend, so the 32-bit view coincided
/// with the 64-bit one and there was nothing to check. One scalar is now loaded 64 bits
/// wide to give alu32 an upper-unknown operand.
#[test]
fn the_sub_register_view_is_actually_exercised() {
    let (_, out) = run_diff(COMP, "reg32");
    assert!(
        out.summary.reg32_checked > 0,
        "alu32 pieces must produce a distinct 32-bit view, or the axis is decorative"
    );
}

/// The denominator. This is the widest runtime denominator any leg has produced, and it
/// is what makes a zero finding count mean something here.
#[test]
fn the_corpus_reaches_the_oracles_in_bulk() {
    let (norm, out) = run_diff(COMP, "base");
    assert_eq!(norm.records.len(), PROGRAMS);
    assert_eq!(
        COMP.matches("RESULT decision=accept").count(), ACCEPTED,
        "the corpus is fixed by its seeds, so this count is reproducible"
    );
    eprintln!(
        "COMP locations_checked={} pairs_checked={} finding_count={}",
        out.summary.store_locations_checked, out.summary.prune_pairs_checked,
        out.summary.finding_count
    );
    assert!(
        out.summary.store_locations_checked >= 900,
        "the runtime oracles must actually be fed: got {}",
        out.summary.store_locations_checked
    );
    assert_eq!(
        out.summary.prune_pairs_checked as usize, PROGRAMS,
        "and every program is usable for the kernel-vs-kernel differential"
    );
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// NOVELTY, which is the entire point: the corpus must contain compositions no
/// hand-written family produced. A generator that emitted one shape forty-eight times
/// would pass every other test here and prove nothing.
#[test]
fn the_corpus_contains_shapes_no_hand_written_family_produced() {
    let all = recipes();
    assert_eq!(all.len(), PROGRAMS, "every program declares its recipe");
    let distinct: BTreeSet<&String> = all.iter().collect();
    assert!(
        distinct.len() >= 80,
        "the walk must actually vary: only {} distinct recipes", distinct.len()
    );
    let kinds: BTreeSet<&str> = all
        .iter()
        .flat_map(|r| r.split(',').filter(|k| !k.is_empty()))
        .collect();
    assert!(
        kinds.len() >= 9,
        "every piece in the pool must actually be reachable from the walk: {kinds:?}"
    );
    let mixed = all
        .iter()
        .filter(|r| {
            let kinds: BTreeSet<&str> = r.split(',').filter(|k| !k.is_empty()).collect();
            kinds.contains("dynptr") && kinds.len() >= 3
        })
        .count();
    assert!(
        mixed > 0,
        "at least one program must combine a dynptr slice with two other piece kinds — \
         that is a shape no earlier family could emit at all"
    );
}

/// Determinism: a finding has to be replayable, so every program carries the seed that
/// produced it.
#[test]
fn every_program_carries_the_seed_that_produced_it() {
    let seeds: Vec<&str> = COMP
        .lines()
        .filter(|l| l.starts_with("COMP "))
        .filter_map(|l| l.split_whitespace().find_map(|t| t.strip_prefix("seed=")))
        .collect();
    assert_eq!(seeds.len(), PROGRAMS);
    assert_eq!(
        seeds.iter().collect::<BTreeSet<_>>().len(), PROGRAMS,
        "distinct seeds, so a single program can be replayed on its own"
    );
}

/// The teeth, on a randomly composed program rather than a designed one.
#[test]
fn the_oracle_has_teeth_on_a_composed_program() {
    let label = COMP
        .split("===PROG ")
        .skip(1)
        .find(|b| b.contains("RESULT decision=accept") && b.contains("RUNTIME input=0x00000000 store_off="))
        .and_then(|b| b.split_whitespace().next())
        .expect("some accepted program must have stored")
        .to_string();
    let mut out_text = String::new();
    let mut hit = false;
    for block in COMP.split("===PROG ").skip(1) {
        out_text.push_str("===PROG ");
        let blabel = block.split_whitespace().next().unwrap();
        for line in block.lines() {
            if blabel == label && line.starts_with("RUNTIME input=0x00000000 ") && !hit {
                out_text.push_str(
                    "RUNTIME input=0x00000000 store_off=63 store_len=1 store_size=1 executed=1");
                hit = true;
            } else {
                out_text.push_str(line);
            }
            out_text.push('\n');
        }
    }
    assert!(hit, "planting target not found");
    let (_, out) = run_diff(&out_text, "teeth");
    assert!(
        out.findings.iter().any(|f| f.kind == "store_location_desync"),
        "a store planted at the far end of the value must fire on a composed program too: \
         {:?}", out.findings
    );
}

#[test]
fn composition_family_opens_no_parser_blind_spot() {
    let (norm, _) = run_diff(COMP, "blind");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}
