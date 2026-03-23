//! # GroundsTo implementations for nexcore-sentinel types
//!
//! Connects SSH brute-force protection types to the Lex Primitiva type system.
//!
//! ## Domain Signature
//!
//! - **∂ (Boundary)**: dominant across the crate -- sentinel IS boundary enforcement
//! - **σ (Sequence)**: auth log line streaming
//! - **μ (Mapping)**: IP → failure timestamps

use nexcore_lex_primitiva::grounding::GroundsTo;
use nexcore_lex_primitiva::primitiva::{LexPrimitiva, PrimitiveComposition};

use crate::config::SentinelConfig;
use crate::error::SentinelError;
use crate::types::{
    AuthEvent, BanDuration, BanRecord, EngineAction, FailureRecord, FindWindow, MaxRetry,
    SentinelState,
};

// ---------------------------------------------------------------------------
// T2-P: Newtypes over Duration/Count
// ---------------------------------------------------------------------------

/// BanDuration: T2-P (∂ + N), dominant ∂
///
/// Duration for which an IP stays banned. Boundary-dominant: the ban IS
/// the boundary enforcement mechanism.
impl GroundsTo for BanDuration {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary, // ∂ -- ban is a boundary
            LexPrimitiva::Quantity, // N -- duration in seconds
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.90)
    }
}

/// FindWindow: T2-P (∂ + ν), dominant ∂
///
/// Sliding window for failure counting. Boundary-dominant: defines the
/// temporal boundary for failure accumulation.
impl GroundsTo for FindWindow {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary,  // ∂ -- temporal boundary
            LexPrimitiva::Frequency, // ν -- rate within window
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.85)
    }
}

/// MaxRetry: T2-P (∂ + N), dominant ∂
///
/// Maximum failures before banning. Boundary-dominant: threshold.
impl GroundsTo for MaxRetry {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary, // ∂ -- threshold limit
            LexPrimitiva::Quantity, // N -- count value
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.90)
    }
}

// ---------------------------------------------------------------------------
// T2-C: Composed types
// ---------------------------------------------------------------------------

/// FailureRecord: T2-C (μ + σ + ν + λ), dominant μ
///
/// Tracks failure timestamps for a single IP. Mapping-dominant: IP → timestamps.
impl GroundsTo for FailureRecord {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Mapping,   // μ -- IP → failure times
            LexPrimitiva::Sequence,  // σ -- ordered timestamps
            LexPrimitiva::Frequency, // ν -- failure rate
            LexPrimitiva::Location,  // λ -- IP address
        ])
        .with_dominant(LexPrimitiva::Mapping, 0.80)
    }
}

// ---------------------------------------------------------------------------
// T3: Domain types
// ---------------------------------------------------------------------------

/// BanRecord: T3 (∂ + λ + σ + N + ∃ + ∝), dominant ∂
///
/// A ban record for a blocked IP. Boundary-dominant: the ban IS the boundary.
impl GroundsTo for BanRecord {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary,        // ∂ -- ban boundary enforcement
            LexPrimitiva::Location,        // λ -- IP address
            LexPrimitiva::Sequence,        // σ -- temporal ordering (banned_at, expires_at)
            LexPrimitiva::Quantity,        // N -- failure count
            LexPrimitiva::Existence,       // ∃ -- expiry check
            LexPrimitiva::Irreversibility, // ∝ -- ban action has consequences
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.85)
    }
}

/// AuthEvent: T3 (∂ + λ + σ + ∃ + → + μ), dominant ∂
///
/// Parsed authentication event. Boundary-dominant: detecting intrusion attempts.
impl GroundsTo for AuthEvent {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary,  // ∂ -- auth boundary violation
            LexPrimitiva::Location,  // λ -- IP address, username
            LexPrimitiva::Sequence,  // σ -- log stream ordering
            LexPrimitiva::Existence, // ∃ -- user validity check
            LexPrimitiva::Causality, // → -- attempt → response
            LexPrimitiva::Mapping,   // μ -- log line → event
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.85)
    }
}

/// SentinelState: T3 (ς + π + σ + ∂ + μ + λ), dominant ς
///
/// Persistent daemon state. State-dominant: serialized checkpoint.
impl GroundsTo for SentinelState {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::State,       // ς -- checkpoint state
            LexPrimitiva::Persistence, // π -- saved to disk
            LexPrimitiva::Sequence,    // σ -- ordered bans/failures
            LexPrimitiva::Boundary,    // ∂ -- active bans
            LexPrimitiva::Mapping,     // μ -- IP → records
            LexPrimitiva::Location,    // λ -- IP addresses
        ])
        .with_dominant(LexPrimitiva::State, 0.80)
    }
}

/// EngineAction: T2-P (→ + ∂), dominant →
///
/// Action the engine should take: None, Ban, RecordFailure.
/// Causality-dominant: the engine decides an action from events.
impl GroundsTo for EngineAction {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Causality, // → -- event → action
            LexPrimitiva::Boundary,  // ∂ -- ban enforcement
        ])
        .with_dominant(LexPrimitiva::Causality, 0.85)
    }
}

/// SentinelConfig: T2-C (∂ + N + ν + π), dominant ∂
///
/// Configuration parameters bounding sentinel behavior.
impl GroundsTo for SentinelConfig {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary,    // ∂ -- thresholds
            LexPrimitiva::Quantity,    // N -- numeric parameters
            LexPrimitiva::Frequency,   // ν -- window rates
            LexPrimitiva::Persistence, // π -- config persistence
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.85)
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// SentinelError: T2-C (∂ + ∅ + → + λ), dominant ∂
///
/// Sentinel errors: parse failures, firewall failures, whitelist checks.
impl GroundsTo for SentinelError {
    fn primitive_composition() -> PrimitiveComposition {
        PrimitiveComposition::new(vec![
            LexPrimitiva::Boundary,  // ∂ -- constraint violations
            LexPrimitiva::Void,      // ∅ -- parse/decode failures
            LexPrimitiva::Causality, // → -- command failures
            LexPrimitiva::Location,  // λ -- IP/path in error
        ])
        .with_dominant(LexPrimitiva::Boundary, 0.85)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use nexcore_lex_primitiva::tier::Tier;

    #[test]
    fn ban_duration_is_boundary_dominant() {
        assert_eq!(
            BanDuration::dominant_primitive(),
            Some(LexPrimitiva::Boundary)
        );
        assert_eq!(BanDuration::tier(), Tier::T2Primitive);
    }

    #[test]
    fn find_window_is_boundary_dominant() {
        assert_eq!(
            FindWindow::dominant_primitive(),
            Some(LexPrimitiva::Boundary)
        );
    }

    #[test]
    fn ban_record_is_t3() {
        assert_eq!(BanRecord::tier(), Tier::T3DomainSpecific);
        assert_eq!(
            BanRecord::dominant_primitive(),
            Some(LexPrimitiva::Boundary)
        );
    }

    #[test]
    fn auth_event_is_boundary_dominant() {
        assert_eq!(
            AuthEvent::dominant_primitive(),
            Some(LexPrimitiva::Boundary)
        );
        assert_eq!(AuthEvent::tier(), Tier::T3DomainSpecific);
    }

    #[test]
    fn sentinel_state_is_state_dominant() {
        assert_eq!(
            SentinelState::dominant_primitive(),
            Some(LexPrimitiva::State)
        );
        assert_eq!(SentinelState::tier(), Tier::T3DomainSpecific);
    }

    #[test]
    fn engine_action_is_causality_dominant() {
        assert_eq!(
            EngineAction::dominant_primitive(),
            Some(LexPrimitiva::Causality)
        );
    }

    #[test]
    fn sentinel_error_is_boundary_dominant() {
        assert_eq!(
            SentinelError::dominant_primitive(),
            Some(LexPrimitiva::Boundary)
        );
    }
}
