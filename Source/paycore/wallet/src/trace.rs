//! Export of scenarios in the envelope of `grinsight.wallet.trace.v1`
//! (research report `REPORT-wallet-model-check.md`), for differential
//! comparison with the wallet model.
//!
//! The model's `expected` object mixes fields owned by several layers. The
//! payment core fills only the ones it decides itself: `status`,
//! `status_rule`, `known`, `spent`, `reserve`, `conflict`. Mode, device,
//! clock, claim, snapshot and archive fields belong to the Fly core and are
//! left out, never guessed. A trace contains no keys, slates, commitments or
//! signing contexts.
use crate::state::{Row, SendStatus};
use serde_json::{json, Map, Value};

/// Schema name shared with the research model.
pub const SCHEMA: &str = "grinsight.wallet.trace.v1";
/// Fields of `expected` the payment core is responsible for.
pub const OWNED_FIELDS: [&str; 6] = [
    "status",
    "status_rule",
    "known",
    "spent",
    "reserve",
    "conflict",
];

/// What the core says about one payment at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// `confirmed`, `preliminary` or `not_confirmed`.
    pub status: &'static str,
    /// Row of the Level 5 table, if one applies.
    pub status_rule: Option<Row>,
    /// A local deal record exists.
    pub known: bool,
    /// The payment's output (incoming) or inputs (outgoing) are spent on chain.
    pub spent: bool,
    /// Inputs are held in reserve for this payment.
    pub reserve: bool,
    /// Another transaction spent one of its inputs (contested or dead).
    pub conflict: bool,
    /// State of an outgoing operation; not part of the model's schema.
    pub send_state: Option<SendStatus>,
}

/// Status word of a Level 5 row.
pub fn status_word(row: Row) -> &'static str {
    match row {
        Row::S8 => "confirmed",
        Row::S4 | Row::S7 => "not_confirmed",
        Row::S1 | Row::S2 | Row::S3 | Row::S6 | Row::S7a => "preliminary",
    }
}

impl Observation {
    /// The `expected` object of one step.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("status".into(), json!(self.status));
        m.insert(
            "status_rule".into(),
            match self.status_rule {
                Some(r) => json!(format!("{r:?}")),
                None => Value::Null,
            },
        );
        m.insert("known".into(), json!(self.known));
        m.insert("spent".into(), json!(self.spent));
        m.insert("reserve".into(), json!(self.reserve));
        m.insert("conflict".into(), json!(self.conflict));
        if let Some(s) = self.send_state {
            m.insert("x_send_state".into(), json!(format!("{s:?}")));
        }
        Value::Object(m)
    }

    /// Names of the owned fields on which a model step disagrees with this
    /// observation. Fields the model step does not carry are not compared.
    pub fn mismatches(&self, model_expected: &Value) -> Vec<&'static str> {
        let ours = self.to_json();
        OWNED_FIELDS
            .iter()
            .copied()
            .filter(|f| match (model_expected.get(*f), ours.get(*f)) {
                (Some(m), Some(o)) => m != o,
                _ => false,
            })
            .collect()
    }
}

/// A scenario being recorded.
#[derive(Clone, Debug)]
pub struct Trace {
    scenario: String,
    initial: Value,
    steps: Vec<Value>,
    last: Value,
}

impl Trace {
    /// Start a scenario from an initial observation.
    pub fn new(scenario: &str, initial: &Observation) -> Trace {
        Trace {
            scenario: scenario.to_string(),
            initial: initial.to_json(),
            steps: Vec::new(),
            last: initial.to_json(),
        }
    }

    /// Record one action and what the core shows after it. `params` must not
    /// contain secrets; amounts, heights and outcomes are fine.
    pub fn step(&mut self, action: &str, params: Value, after: &Observation) {
        self.last = after.to_json();
        self.steps.push(json!({
            "action": action,
            "params": params,
            "expected": self.last,
        }));
    }

    /// Number of recorded steps.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// True if nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// The trace document.
    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "scenario": self.scenario,
            "tick_seconds": 15,
            "producer": "fly-paycore-wallet",
            "owned_fields": OWNED_FIELDS,
            "initial": self.initial,
            "steps": self.steps,
            "result": self.last,
        })
    }
}
