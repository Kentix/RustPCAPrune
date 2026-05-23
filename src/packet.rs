//! Shared per-packet slim decision (read path for slim and analyze).

use crate::parse::parse_frame;
use crate::policy::{decide_action, Action};
use crate::truncate::apply_truncate_on_parsed;

/// Result of processing one frame — avoids copying on keep.
#[derive(Debug)]
pub enum PacketOutcome {
    Keep,
    Truncated(Vec<u8>),
}

/// Returns outcome and whether the payload was truncated.
pub fn process_packet(frame: &[u8]) -> (PacketOutcome, bool) {
    let Ok(parsed) = parse_frame(frame) else {
        return (PacketOutcome::Keep, false);
    };

    match decide_action(&parsed) {
        Action::Keep => (PacketOutcome::Keep, false),
        Action::Truncate => {
            let mut buf = frame.to_vec();
            if apply_truncate_on_parsed(&mut buf, &parsed) {
                (PacketOutcome::Truncated(buf), true)
            } else {
                (PacketOutcome::Keep, false)
            }
        }
    }
}
