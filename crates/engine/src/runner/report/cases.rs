//! Each test a report named and how it ended: what a test an agent names for
//! a criterion is matched against. The counts stay in [`Tested`].

use crate::verdict::Tested;

/// The most tests named from one run; the counts stay exact past it.
pub const MOST_CASES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Failed,
    Skipped,
}

impl Outcome {
    pub fn word(self) -> &'static str {
        match self {
            Outcome::Passed => "passed",
            Outcome::Failed => "failed",
            Outcome::Skipped => "skipped",
        }
    }
}

/// One test, as its report named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub name: String,
    /// The file, or the class or suite the report put it under.
    pub place: Option<String>,
    pub outcome: Outcome,
}

/// What a run's reports said: the counts, and each test by name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reported {
    pub tested: Tested,
    pub cases: Vec<Case>,
}

impl Reported {
    pub(super) fn of(tested: Tested) -> Self {
        Reported {
            tested,
            cases: Vec::new(),
        }
    }

    pub(super) fn add(&mut self, other: Reported) {
        self.tested.add(other.tested);
        let room = MOST_CASES.saturating_sub(self.cases.len());
        self.cases.extend(other.cases.into_iter().take(room));
    }

    pub(super) fn case(&mut self, name: &str, place: Option<String>, outcome: Outcome) {
        if self.cases.len() < MOST_CASES {
            self.cases.push(Case {
                name: name.to_owned(),
                place,
                outcome,
            });
        }
    }
}

/// Where one name ends and the next part of a test's path begins.
const SEPARATORS: &[char] = &[':', '.', '/', '#', ' ', '>', '›'];

/// How the test `named` ended: failed when any case it names failed, passed
/// when one passed and none failed, `None` when no case is it.
pub fn outcome_of(named: &str, cases: &[Case]) -> Option<Outcome> {
    cases
        .iter()
        .filter(|case| names(named, case))
        .fold(None, |found, case| {
            Some(match (found, case.outcome) {
                (Some(Outcome::Failed), _) | (_, Outcome::Failed) => Outcome::Failed,
                (Some(Outcome::Passed), _) | (_, Outcome::Passed) => Outcome::Passed,
                _ => Outcome::Skipped,
            })
        })
}

/// Whether `named` — `tests/test_cli.py::test_rename`, `rename changes the
/// title`, `tests::adds` — is this case: the same name, or one ending in the
/// other right after a separator.
fn names(named: &str, case: &Case) -> bool {
    let named = named.trim();
    let ends = |long: &str, short: &str| {
        long == short
            || long
                .strip_suffix(short)
                .is_some_and(|before| before.ends_with(SEPARATORS))
    };
    !named.is_empty()
        && std::iter::once(case.name.as_str())
            .chain(base(&case.name))
            .any(|name| !name.is_empty() && (ends(named, name) || ends(name, named)))
}

/// The test a parameterized case is one run of, so naming the test names every
/// run: PHPUnit's `… with data set #0`, Pest's `… with ('a')`, pytest's
/// `test_x[a-b]`, a Go subtest's `TestX/case`.
pub(crate) fn base(name: &str) -> Option<&str> {
    let go = ["Test", "Example", "Fuzz", "Benchmark"]
        .iter()
        .any(|prefix| name.starts_with(prefix));
    let cut = name
        .find(" with data set ")
        .or_else(|| name.find(" with ("))
        .or_else(|| name.ends_with(']').then(|| name.find('[')).flatten())
        .or_else(|| go.then(|| name.find('/')).flatten())?;
    Some(name[..cut].trim_end()).filter(|base| !base.is_empty())
}
