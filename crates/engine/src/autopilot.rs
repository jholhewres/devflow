//! Autopilot: once the person approved a plan, its cards go one after
//! another in the order their blockers allow, one session per card, each
//! through the gate. This is the pure half — what comes next, from where the
//! cards stand. The app launches each session through its own code and asks
//! again when a card finishes or moves.
//!
//! It stops only for the person: a card finished that another waits on (the
//! person checks it and moves it to done), a flow that asks the person to
//! approve each card, a session stopped on a question, or a card that cannot
//! start at all.

/// Where a card of the plan stands, by its lane and its sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Not started.
    Waiting,
    /// In the lane for work in progress, a session at it.
    Working,
    /// Its session stopped on the person, or ended before the card finished.
    Stuck(String),
    /// It passed the gate and waits to be checked.
    Finished,
    Done,
}

/// One card of the plan, with what blocks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub id: String,
    pub title: String,
    /// Each blocker's id, and whether it is done.
    pub blocked_by: Vec<(String, bool)>,
    pub standing: Standing,
}

/// What the autopilot does now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// A session starts on this card.
    Start(String),
    /// A session is at work on this card: nothing to do until it finishes.
    Working(String),
    /// Stopped for the person's approval of this card.
    Approve { card: String, why: String },
    /// Stopped on a blocker only the person can clear.
    Blocked { card: String, why: String },
    /// Every card passed its gate.
    Done,
}

/// The cards in an order where every blocker comes first, the plan's own
/// order kept wherever the blockers allow; refused on a cycle.
pub fn ordered(cards: &[Planned]) -> Result<Vec<&Planned>, String> {
    let mut placed: Vec<&Planned> = Vec::with_capacity(cards.len());
    while placed.len() < cards.len() {
        let ready = cards.iter().find(|card| {
            !placed.iter().any(|one| one.id == card.id)
                && card.blocked_by.iter().all(|(by, _)| {
                    placed.iter().any(|one| one.id == *by) || !cards.iter().any(|one| one.id == *by)
                })
        });
        match ready {
            Some(card) => placed.push(card),
            None => {
                let left: Vec<&str> = cards
                    .iter()
                    .filter(|card| !placed.iter().any(|one| one.id == card.id))
                    .map(|card| card.title.as_str())
                    .collect();
                return Err(format!(
                    "the plan's cards wait on each other: {}",
                    left.join(", ")
                ));
            }
        }
    }
    Ok(placed)
}

/// What comes next for `cards`. `approve_each` is a flow that asks the
/// person to approve every card once it finished.
pub fn next(cards: &[Planned], approve_each: bool) -> Next {
    let order = match ordered(cards) {
        Ok(order) => order,
        Err(why) => {
            return Next::Blocked {
                card: cards
                    .first()
                    .map(|card| card.id.clone())
                    .unwrap_or_default(),
                why,
            }
        }
    };
    if let Some(card) = order
        .iter()
        .find(|card| matches!(card.standing, Standing::Stuck(_)))
    {
        let Standing::Stuck(why) = &card.standing else {
            unreachable!("found as stuck")
        };
        return Next::Blocked {
            card: card.id.clone(),
            why: why.clone(),
        };
    }
    // One session at a time: the next card builds on what this one leaves.
    if let Some(card) = order.iter().find(|card| card.standing == Standing::Working) {
        return Next::Working(card.id.clone());
    }
    if approve_each {
        if let Some(card) = order
            .iter()
            .find(|card| card.standing == Standing::Finished)
        {
            return Next::Approve {
                card: card.id.clone(),
                why: format!(
                    "\"{}\" passed its gate, and the flow asks you to approve each card: check it and move it to done",
                    card.title
                ),
            };
        }
    }
    let title = |id: &str| {
        cards
            .iter()
            .find(|card| card.id == id)
            .map_or(id.to_owned(), |card| card.title.clone())
    };
    let mut waiting_on: Option<Next> = None;
    for card in order
        .iter()
        .filter(|card| card.standing == Standing::Waiting)
    {
        let open: Vec<&(String, bool)> =
            card.blocked_by.iter().filter(|(_, done)| !*done).collect();
        if open.is_empty() {
            return Next::Start(card.id.clone());
        }
        if waiting_on.is_some() {
            continue;
        }
        for (by, _) in open {
            let blocker = cards.iter().find(|one| one.id == *by);
            waiting_on = match blocker.map(|one| &one.standing) {
                Some(Standing::Finished) => Some(Next::Approve {
                    card: by.clone(),
                    why: format!(
                        "\"{}\" waits on \"{}\", which passed its gate: check it and move it to done",
                        card.title,
                        title(by)
                    ),
                }),
                None => Some(Next::Blocked {
                    card: card.id.clone(),
                    why: format!(
                        "\"{}\" waits on \"{}\", which is not part of this plan and not done",
                        card.title,
                        title(by)
                    ),
                }),
                _ => continue,
            };
            break;
        }
    }
    match waiting_on {
        Some(stop) => stop,
        None if order.iter().any(|card| card.standing == Standing::Waiting) => Next::Blocked {
            card: String::new(),
            why: "no card of the plan can start".to_owned(),
        },
        None => Next::Done,
    }
}

#[cfg(test)]
#[path = "autopilot_tests.rs"]
mod tests;
