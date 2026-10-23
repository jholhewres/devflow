//! How well a rubric agrees with the person, and where its line would agree
//! best: from the decisions the person labelled by what they did — reopening
//! a card Jev called done, calling a finding a false positive, finishing a
//! card. The model is never trained; only a rubric's thresholds move.
//!
//! Pure: the decision log is the app's.

/// One labelled decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Labelled {
    /// What its passing turned on: the lowest of its yes/no answers held
    /// to a `min`. `None` when it had none.
    pub score: Option<f64>,
    /// `pass`, `grey` or `fail`, as its thresholds judged it then.
    pub outcome: String,
    /// The person found it passing.
    pub truth: bool,
}

/// A threshold that would have agreed with the person most.
#[derive(Debug, Clone, PartialEq)]
pub struct Suggested {
    pub min: f64,
    /// Below `min` and at or above this, a person looks.
    pub grey: Option<f64>,
    /// Of the labelled decisions, at `min`.
    pub accuracy: f64,
}

/// How a rubric did.
#[derive(Debug, Clone, PartialEq)]
pub struct Calibration {
    pub labelled: usize,
    /// Labelled, and not left grey.
    pub decided: usize,
    pub agreed: usize,
    pub grey: usize,
    /// `agreed` of `decided`.
    pub accuracy: Option<f64>,
    pub suggested: Option<Suggested>,
    pub note: Option<String>,
}

/// Labels a threshold is suggested from, at least: fewer is a guess.
pub const FEWEST: usize = 8;

/// The lines tried: 0.05 to 0.95, in hundredths so they compare exactly.
const STEPS: std::ops::RangeInclusive<u32> = 1..=19;

fn at(step: u32) -> f64 {
    f64::from(step * 5) / 100.0
}

fn agreeing(samples: &[(f64, bool)], line: f64) -> usize {
    samples
        .iter()
        .filter(|(score, truth)| (*score >= line) == *truth)
        .count()
}

/// The `min` that agrees most with the person — the middle of the best
/// stretch, so one more label moves it least — and the `grey` below which
/// at least nine in ten were failing.
pub fn suggested(samples: &[(f64, bool)]) -> Option<Suggested> {
    if samples.len() < FEWEST {
        return None;
    }
    let counts: Vec<(u32, usize)> = STEPS
        .map(|step| (step, agreeing(samples, at(step))))
        .collect();
    let best = counts.iter().map(|(_, count)| *count).max()?;
    let first = counts.iter().position(|(_, count)| *count == best)?;
    let last = counts[first..]
        .iter()
        .take_while(|(_, count)| *count == best)
        .count()
        + first
        - 1;
    let (step, _) = counts[(first + last) / 2];
    let grey = (*STEPS.start()..step)
        .rev()
        .find(|below| {
            let under: Vec<&(f64, bool)> = samples
                .iter()
                .filter(|(score, _)| *score < at(*below))
                .collect();
            let failing = under.iter().filter(|(_, truth)| !truth).count();
            !under.is_empty() && failing * 10 >= under.len() * 9
        })
        .map(at);
    Some(Suggested {
        min: at(step),
        grey,
        accuracy: best as f64 / samples.len() as f64,
    })
}

/// Whether a decision's outcome is one Jev reached. `skipped` is a call that
/// never answered: not a decision, so never counted or labelled as one.
pub fn decided(outcome: &str) -> bool {
    matches!(outcome, "pass" | "grey" | "fail")
}

/// A rubric's agreement with the person at the thresholds it had, and the
/// one it would have agreed best at.
pub fn calibrated(labelled: &[Labelled]) -> Calibration {
    let judged: Vec<&Labelled> = labelled
        .iter()
        .filter(|one| decided(&one.outcome))
        .collect();
    let grey = judged.iter().filter(|one| one.outcome == "grey").count();
    let decided = judged.len() - grey;
    let agreed = judged
        .iter()
        .filter(|one| one.outcome != "grey" && (one.outcome == "pass") == one.truth)
        .count();
    let samples: Vec<(f64, bool)> = judged
        .iter()
        .filter_map(|one| Some((one.score?, one.truth)))
        .collect();
    let suggested = suggested(&samples);
    Calibration {
        labelled: judged.len(),
        decided,
        agreed,
        grey,
        accuracy: (decided > 0).then(|| agreed as f64 / decided as f64),
        note: suggested.is_none().then(|| {
            format!(
                "{} labelled so far: a threshold is suggested from {FEWEST}",
                samples.len()
            )
        }),
        suggested,
    }
}

/// The decisions the person confirmed before a rubric that sets findings
/// aside may act: fewer says nothing about what it would drop.
pub const ENFORCE_AFTER: usize = 20;
/// The most of those it may have failed: in 0.43 it failed half of them.
pub const ENFORCE_MOST_FAILING: f64 = 0.10;

/// Of the decisions the person confirmed, how many Jev failed, and of how many.
pub fn failing_confirmed(labelled: &[Labelled]) -> (usize, usize) {
    let confirmed: Vec<&Labelled> = labelled
        .iter()
        .filter(|one| one.truth && decided(&one.outcome))
        .collect();
    let failed = confirmed.iter().filter(|one| one.outcome == "fail").count();
    (failed, confirmed.len())
}

/// Whether a rubric may act in enforce: `Err` says why it stays in shadow.
pub fn enforceable(labelled: &[Labelled]) -> Result<(), String> {
    let (failed, confirmed) = failing_confirmed(labelled);
    if confirmed < ENFORCE_AFTER {
        return Err(format!(
            "enforce waits for {ENFORCE_AFTER} decisions you confirmed, and has {confirmed}"
        ));
    }
    if failed as f64 > confirmed as f64 * ENFORCE_MOST_FAILING {
        return Err(format!(
            "it failed {failed} of {confirmed} findings you confirmed, more than {}%",
            (ENFORCE_MOST_FAILING * 100.0).round()
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "calibrate_tests.rs"]
mod tests;
