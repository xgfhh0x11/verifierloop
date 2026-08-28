//! Ground-truth source 2 (documented behaviour) — calibration on the real path.
//!
//! The same two-sided proof the other detector legs got: the check must stay SILENT
//! when the kernel agrees with its documentation, and must FIRE when they disagree.
//! Plus the provenance question this source raises specifically: the expectation
//! must come from the document (anchor-verified), so a drifted quote disables the
//! case instead of asserting a claim the document no longer makes.

use contract::PeriodPaths;
use pipeline::groundtruth::verifier_rst::{self, DocumentedOutcome};
use pipeline::groundtruth::{GroundTruth, NoGroundTruth, StaticGroundTruth};
use pipeline::ingest::{self, Source};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, normalize};

/// A real harness block for a documented case, in the native format.
fn block(label: &str, decision: &str) -> String {
    format!(
        "===PROG {label} type=socket_filter ===\n\
         RESULT decision={decision} fd=3 errno=0 load_ns=1\n\
         ---LOG---\n\
         0: R1=ctx() R10=fp0\n\
         0: (b7) r0 = 0                        ; R0=0\n\
         1: (95) exit\n\
         processed 2 insns (limit 1000000) total_states 0 peak_states 0\n\
         ---END---\n"
    )
}

/// The document as shipped in the tree (its own words are the expectation).
const DOC: &str = "\
If register was never written to, it's not readable::

  bpf_mov R0 = R2
  bpf_exit

will be rejected, since R2 is unreadable at the start of the program.

::

  bpf_mov R6 = 1
  bpf_call foo
  bpf_mov R0 = R6
  bpf_exit

is a correct program.

For example::

 bpf_mov R1 = 1
 bpf_xadd *(u32 *)(R1 + 3) += R2
 bpf_exit

will be rejected, since R1 doesn't have a valid pointer type at the time of
execution of instruction bpf_xadd.
";

fn run(native: &str, gt: &dyn GroundTruth, tag: &str) -> diff::DiffFindings {
    let dir = std::env::temp_dir().join(format!("vl-doc-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("diffharness.log");
    std::fs::write(&src, native).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("diffharness", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, gt).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn gt_with_doc() -> StaticGroundTruth {
    StaticGroundTruth::default().with_verifier_rst(verifier_rst::from_text(DOC))
}

fn doc_findings(out: &diff::DiffFindings) -> Vec<&diff::DivergenceFinding> {
    out.findings
        .iter()
        .filter(|f| f.kind == "documented_behavior_mismatch")
        .collect()
}

#[test]
fn silent_when_the_kernel_agrees_with_its_documentation() {
    // The document says this program is rejected; the kernel rejected it.
    let out = run(&block("doc_unreadable_reg", "reject"), &gt_with_doc(), "agree");
    assert!(doc_findings(&out).is_empty(), "false positive: {:?}", out.findings);
    assert_eq!(out.summary.documented_cases_checked, 1, "the case WAS compared");
}

#[test]
fn fires_when_the_kernel_contradicts_its_documentation() {
    // Same program, but the verifier ACCEPTED what the document says is rejected —
    // the documented-vs-observed divergence this source exists to catch.
    let out = run(&block("doc_unreadable_reg", "accept"), &gt_with_doc(), "disagree");
    let f = doc_findings(&out);
    assert_eq!(f.len(), 1, "the mismatch must be reported: {:?}", out.findings);
    assert_eq!(f[0].expected, "reject");
    assert_eq!(f[0].observed, "accept");
    assert_eq!(
        f[0].source,
        diff::GroundTruthSource::Documentation,
        "attributed to the documentation, not to an intrinsic invariant"
    );
}

#[test]
fn the_expectation_comes_from_the_document_not_the_checker() {
    // With no ground truth loaded, the very same contradiction produces nothing:
    // the claim lives in the document, not in the diff stage.
    let out = run(&block("doc_unreadable_reg", "accept"), &NoGroundTruth, "nogt");
    assert!(doc_findings(&out).is_empty());
    assert_eq!(out.summary.documented_cases_checked, 0, "nothing to compare against");
}

#[test]
fn a_drifted_quote_disables_the_case_instead_of_asserting_a_stale_claim() {
    // The documentation is reworded, so the anchor no longer matches. The case must
    // go quiet — asserting an expectation the document no longer makes would be
    // fabricating ground truth.
    let reworded = DOC.replace(
        "will be rejected, since R2 is unreadable at the start of the program",
        "is refused because R2 holds no value yet",
    );
    let model = verifier_rst::from_text(&reworded);
    assert!(model.stale().contains(&"doc_unreadable_reg".to_string()));

    let gt = StaticGroundTruth::default().with_verifier_rst(model);
    let out = run(&block("doc_unreadable_reg", "accept"), &gt, "stale");
    assert!(
        doc_findings(&out).is_empty(),
        "a stale case must not assert anything: {:?}",
        out.findings
    );
    assert_eq!(out.summary.documented_cases_checked, 0);
}

#[test]
fn unrelated_programs_are_untouched_by_this_source() {
    // A syzkaller replay block has no documented claim; the leg must ignore it.
    let out = run(&block("b4f4197b8455#0", "accept"), &gt_with_doc(), "unrelated");
    assert!(doc_findings(&out).is_empty());
    assert_eq!(out.summary.documented_cases_checked, 0);
}

#[test]
fn all_three_documented_cases_are_checkable_and_agree_when_correct() {
    let native = format!(
        "{}{}{}",
        block("doc_unreadable_reg", "reject"),
        block("doc_callee_saved_r6", "accept"),
        block("doc_bad_ptr_xadd", "reject"),
    );
    let out = run(&native, &gt_with_doc(), "all");
    assert_eq!(out.summary.documented_cases_checked, 3, "all three compared");
    assert!(doc_findings(&out).is_empty(), "{:?}", out.findings);
    assert_eq!(
        verifier_rst::from_text(DOC).outcome("doc_callee_saved_r6"),
        Some(DocumentedOutcome::Accept)
    );
}
