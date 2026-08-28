//! Ground-truth source 2 — `Documentation/bpf/verifier.rst` (documented behavior).
//!
//! The document is prose, so there is no honest way to *derive* rules from it
//! mechanically. What it DOES contain is a set of explicit behavioural claims of
//! the form "this program is rejected / is a correct program", each next to an
//! example program. Those are executable: run the documented program, compare the
//! observed verifier decision against the documented one. A difference is a real
//! documented-vs-observed divergence — the bug class intrinsic invariants and
//! helper contracts cannot see.
//!
//! PROVENANCE DISCIPLINE. Each case below carries the document's own sentence
//! verbatim plus its line number. [`load`] re-reads the file and CHECKS that the
//! quote is still present: if the documentation changes, the case is reported as
//! STALE instead of being silently trusted. So the expectation's origin is
//! verifiable, and drift is loud. (The pseudo-asm -> real insn translation lives in
//! `harness/diffharness.c` next to each case id; that translation is a reviewable
//! judgement, the same shape as `helper_proto::SINGLE_FAMILY_ARG_TYPES`.)

use std::collections::BTreeMap;
use std::path::Path;

/// What the documentation says the verifier does with a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentedOutcome {
    /// The document calls it a correct/valid program.
    Accept,
    /// The document says it is rejected.
    Reject,
}

/// One documented behavioural claim, anchored to the sentence that makes it.
#[derive(Debug, Clone)]
pub struct DocumentedCase {
    /// Stable id; the harness emits a program with this exact label.
    pub id: &'static str,
    /// Line in `Documentation/bpf/verifier.rst` the claim is made on (for triage).
    pub doc_line: u32,
    /// The document's own words, verbatim — the anchor `load` verifies.
    pub quote: &'static str,
    /// What the document says happens.
    pub outcome: DocumentedOutcome,
}

/// The documented cases this loader knows how to check.
///
/// Deliberately small and literal: every entry is a sentence the document states
/// outright, not an inference from it. Adding a case means finding another explicit
/// claim, not interpreting prose.
pub const DOCUMENTED_CASES: &[DocumentedCase] = &[
    DocumentedCase {
        id: "doc_unreadable_reg",
        doc_line: 30,
        quote: "will be rejected, since R2 is unreadable at the start of the program",
        outcome: DocumentedOutcome::Reject,
    },
    DocumentedCase {
        id: "doc_callee_saved_r6",
        doc_line: 45,
        quote: "is a correct program",
        outcome: DocumentedOutcome::Accept,
    },
    DocumentedCase {
        id: "doc_bad_ptr_xadd",
        doc_line: 56,
        quote: "will be rejected, since R1 doesn't have a valid pointer type",
        outcome: DocumentedOutcome::Reject,
    },
];

/// Documented behaviour loaded from the tree, with drift accounted for.
#[derive(Debug, Default, Clone)]
pub struct VerifierRstModel {
    /// Cases whose anchoring quote was found in the document (usable).
    verified: BTreeMap<String, DocumentedOutcome>,
    /// Cases whose quote was NOT found — the document moved on. Reported, never
    /// silently used: a stale expectation is worse than no expectation.
    stale: Vec<String>,
}

impl VerifierRstModel {
    /// The documented outcome for `case_id`, if its anchor was verified.
    pub fn outcome(&self, case_id: &str) -> Option<DocumentedOutcome> {
        self.verified.get(case_id).copied()
    }

    /// Number of usable (anchor-verified) cases.
    pub fn len(&self) -> usize {
        self.verified.len()
    }

    /// Whether nothing usable was loaded.
    pub fn is_empty(&self) -> bool {
        self.verified.is_empty()
    }

    /// Case ids whose documented sentence is no longer in the file (drift).
    pub fn stale(&self) -> &[String] {
        &self.stale
    }
}

/// Load documented behaviour from a bpf-next checkout.
///
/// `kernel_src` is the tree root; the file read is
/// `Documentation/bpf/verifier.rst`. Each case is admitted ONLY if its verbatim
/// quote is still present in the document.
pub fn load(kernel_src: &Path) -> std::io::Result<VerifierRstModel> {
    let text = std::fs::read_to_string(kernel_src.join("Documentation/bpf/verifier.rst"))?;
    Ok(from_text(&text))
}

/// Build the model from the document's text (exposed for testing).
pub fn from_text(text: &str) -> VerifierRstModel {
    // Join wrapped lines: the document hard-wraps prose, so a quoted sentence may
    // span two lines. Compare against a whitespace-normalised single line.
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut model = VerifierRstModel::default();
    for case in DOCUMENTED_CASES {
        let needle: String = case.quote.split_whitespace().collect::<Vec<_>>().join(" ");
        if flat.contains(&needle) {
            model.verified.insert(case.id.to_string(), case.outcome);
        } else {
            model.stale.push(case.id.to_string());
        }
    }
    model
}

#[cfg(test)]
mod tests {
    use super::*;

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

is a correct program. If there was R1 instead of R6, it would have
been rejected.

For example::

 bpf_mov R1 = 1
 bpf_xadd *(u32 *)(R1 + 3) += R2
 bpf_exit

will be rejected, since R1 doesn't have a valid pointer type at the time of
execution of instruction bpf_xadd.
";

    #[test]
    fn admits_cases_whose_quote_is_present() {
        let m = from_text(DOC);
        assert_eq!(m.len(), 3, "all three documented claims anchor");
        assert!(m.stale().is_empty());
        assert_eq!(m.outcome("doc_unreadable_reg"), Some(DocumentedOutcome::Reject));
        assert_eq!(m.outcome("doc_callee_saved_r6"), Some(DocumentedOutcome::Accept));
        assert_eq!(m.outcome("doc_bad_ptr_xadd"), Some(DocumentedOutcome::Reject));
    }

    #[test]
    fn quotes_match_across_the_documents_hard_wrapping() {
        // The xadd claim is wrapped mid-sentence in the real file; normalisation
        // must still find it.
        assert!(DOC.contains("will be rejected, since R1 doesn't have a valid pointer type at the time of\nexecution"));
        assert_eq!(from_text(DOC).outcome("doc_bad_ptr_xadd"), Some(DocumentedOutcome::Reject));
    }

    #[test]
    fn drift_is_reported_not_silently_trusted() {
        // Documentation reworded: the anchor disappears -> the case must go STALE,
        // never keep asserting an expectation the document no longer makes.
        let reworded = DOC.replace(
            "will be rejected, since R2 is unreadable at the start of the program",
            "is refused because R2 holds no value yet",
        );
        let m = from_text(&reworded);
        assert_eq!(m.outcome("doc_unreadable_reg"), None, "stale case must not be usable");
        assert!(m.stale().contains(&"doc_unreadable_reg".to_string()));
        assert_eq!(m.len(), 2, "the other two still anchor");
    }
}
