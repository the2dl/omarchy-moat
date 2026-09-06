//! The weekly digest (LEARNING §5).
//!
//! One normal-urgency notification a week — "moat: 0 needed you, 4812 recorded,
//! 1193 suppressed, 18 installs watched, 3 baseline proposals to review" — and
//! it is the **only** scheduled
//! notification moat ever sends. Its job is to remind the user the thing is on
//! and working without becoming noise, which is why it says how much was
//! watched, not just what was wrong.
//!
//! ## Who sends it
//!
//! The daemon computes the summary and publishes it in `state.json`
//! (`digest_summary = {due, text, …}`); it does **not** send anything, because
//! it is a system service with no session bus and desktop notifications belong
//! to the user's session. Delivery is a **user** timer,
//! `systemd/user/moat-digest.timer`, which runs
//! `moatctl digest --notify` weekly; that reads the summary over the socket and
//! calls `omarchy-notification-send`. The plugin can show the same summary
//! without the timer, since it is in `state.json` either way.
//!
//! `moatctl set digest off` flips `digest_enabled` in `state.json`; the timer
//! still fires and `--notify` then does nothing, so turning it off never needs
//! root or `systemctl`.

use chrono::{Datelike, Local, NaiveTime, TimeZone, Timelike};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// What one week looked like.
///
/// `needed_you` / `recorded` / `suppressed` are the same three words
/// `moatctl status` prints and the same three populations `AlertStore::ledger`
/// counts, in the past tense. The digest is the one message a person reads
/// without having asked for it, so it is the last place two different numbers
/// should share one word: "0 incidents" next to a badge of 13 and a status
/// screen saying "unacked 1,854" is three answers to one question.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// High and critical alerts that were not suppressed and were not `signal`
    /// building blocks: the ones that asked for a person.
    pub incidents: u64,
    /// Timeline rows written in the window. Seen, written down, not asked
    /// about.
    pub recorded: u64,
    /// Rows an allowlist entry matched: recorded and never counted
    /// (BASELINE §8).
    pub suppressed: u64,
    /// Install receipts, i.e. package-manager subtrees that ran to completion.
    pub installs: u64,
    /// Baseline proposals waiting for a decision.
    pub proposals: u64,
}

impl Summary {
    /// The notification body of LEARNING §5.
    pub fn text(&self) -> String {
        format!(
            "moat: {} needed you, {} recorded, {} suppressed, {} install{} watched, {} baseline \
             proposal{} to review",
            self.incidents,
            self.recorded,
            self.suppressed,
            self.installs,
            plural(self.installs),
            self.proposals,
            plural(self.proposals),
        )
    }

    /// Urgency for `omarchy-notification-send`. LEARNING §5 says normal; a week
    /// with something in it is still normal, because the incident itself already
    /// notified when it happened.
    pub fn urgency(&self) -> &'static str {
        "normal"
    }
}

fn plural(n: u64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// `monday` … `sunday`, case-insensitive and prefix-tolerant (`mon`).
pub fn weekday_of(name: &str) -> Option<chrono::Weekday> {
    let n = name.trim().to_ascii_lowercase();
    let all = [
        chrono::Weekday::Mon,
        chrono::Weekday::Tue,
        chrono::Weekday::Wed,
        chrono::Weekday::Thu,
        chrono::Weekday::Fri,
        chrono::Weekday::Sat,
        chrono::Weekday::Sun,
    ];
    let names = [
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    ];
    for (i, full) in names.iter().enumerate() {
        if *full == n || (n.len() >= 3 && full.starts_with(&n)) {
            return Some(all[i]);
        }
    }
    None
}

/// The next `weekday` at `hour` **local time**, strictly after `now`.
///
/// Local, not UTC: "Monday 9am" is a promise about the user's morning, and a
/// digest that arrives at 2am because the machine is in UTC+9 is noise.
pub fn next_due(now: u64, weekday: &str, hour: u32) -> u64 {
    let wd = weekday_of(weekday).unwrap_or(chrono::Weekday::Mon);
    let hour = hour.min(23);
    let now_dt = match Local.timestamp_opt(now as i64, 0).single() {
        Some(d) => d,
        None => return now + 7 * 86_400,
    };
    let time = NaiveTime::from_hms_opt(hour, 0, 0).unwrap_or_else(|| {
        NaiveTime::from_hms_opt(9, 0, 0).expect("09:00 is a valid time")
    });
    // Walk at most 8 days: one full week plus today.
    for step in 0..=8 {
        let day = now_dt.date_naive() + chrono::Duration::days(step);
        if day.weekday() != wd {
            continue;
        }
        let naive = day.and_time(time);
        // A DST-ambiguous local time resolves to the earliest instant; a
        // non-existent one (spring forward) falls back to the hour after.
        let dt = Local
            .from_local_datetime(&naive)
            .earliest()
            .or_else(|| Local.from_local_datetime(&(day.and_time(time) + chrono::Duration::hours(1))).earliest());
        if let Some(dt) = dt {
            let secs = dt.timestamp() as u64;
            if secs > now {
                return secs;
            }
        }
    }
    now + 7 * 86_400
}

/// The `digest_summary` block of `state.json`, and the `digest` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    pub enabled: bool,
    pub due: u64,
    pub last_sent: u64,
    pub summary: Summary,
    pub weekday: String,
    pub hour: u32,
}

impl Digest {
    pub fn to_json(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "due": crate::util::rfc3339_of(self.due),
            "due_unix": self.due,
            "last_sent": if self.last_sent == 0 {
                Value::Null
            } else {
                Value::from(crate::util::rfc3339_of(self.last_sent))
            },
            "text": self.summary.text(),
            "urgency": self.summary.urgency(),
            "weekday": self.weekday,
            "hour": self.hour,
            "incidents": self.summary.incidents,
            "needs_you": self.summary.incidents,
            "recorded": self.summary.recorded,
            "suppressed": self.summary.suppressed,
            "installs": self.summary.installs,
            "proposals": self.summary.proposals,
        })
    }

    /// Is it time? The timer is weekly, so this only guards against a manual
    /// `--notify` (or a catch-up run after a suspend) sending twice.
    pub fn due_now(&self, now: u64) -> bool {
        self.enabled && now >= self.due
    }
}

/// Local hour of a unix timestamp, for the tests and for logging.
pub fn local_hour(secs: u64) -> u32 {
    Local
        .timestamp_opt(secs as i64, 0)
        .single()
        .map(|d| d.hour())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_is_the_sentence_from_the_doc() {
        let s = Summary {
            incidents: 0,
            recorded: 4_812,
            suppressed: 1_193,
            installs: 18,
            proposals: 3,
        };
        assert_eq!(
            s.text(),
            "moat: 0 needed you, 4812 recorded, 1193 suppressed, 18 installs watched, \
             3 baseline proposals to review"
        );
        let one = Summary {
            incidents: 1,
            recorded: 1,
            suppressed: 1,
            installs: 1,
            proposals: 1,
        };
        assert_eq!(
            one.text(),
            "moat: 1 needed you, 1 recorded, 1 suppressed, 1 install watched, \
             1 baseline proposal to review"
        );
        assert_eq!(s.urgency(), "normal");
    }

    #[test]
    fn weekday_names_are_forgiving() {
        assert_eq!(weekday_of("monday"), Some(chrono::Weekday::Mon));
        assert_eq!(weekday_of("  Sunday "), Some(chrono::Weekday::Sun));
        assert_eq!(weekday_of("thu"), Some(chrono::Weekday::Thu));
        assert_eq!(weekday_of("caturday"), None);
    }

    #[test]
    fn the_next_due_is_that_weekday_at_that_hour_and_always_in_the_future() {
        let now = crate::util::unix_secs();
        for day in ["monday", "friday", "sunday"] {
            for hour in [0u32, 9, 23] {
                let due = next_due(now, day, hour);
                assert!(due > now, "{} {} is not in the future", day, hour);
                assert!(due - now <= 8 * 86_400, "more than a week away");
                let d = Local.timestamp_opt(due as i64, 0).single().unwrap();
                assert_eq!(d.weekday(), weekday_of(day).unwrap());
                // DST can shift the hour by one; anything else is a bug.
                assert!(
                    d.hour() == hour || d.hour() == (hour + 1) % 24,
                    "{} {} landed at {}",
                    day,
                    hour,
                    d.hour()
                );
            }
        }
        // A bad weekday falls back to Monday rather than never firing.
        let due = next_due(now, "caturday", 9);
        assert_eq!(
            Local.timestamp_opt(due as i64, 0).single().unwrap().weekday(),
            chrono::Weekday::Mon
        );
        // An impossible hour is clamped, not panicked on.
        assert!(next_due(now, "monday", 99) > now);
    }

    #[test]
    fn due_now_respects_the_off_switch() {
        let d = Digest {
            enabled: true,
            due: 1_000,
            last_sent: 0,
            summary: Summary::default(),
            weekday: "monday".into(),
            hour: 9,
        };
        assert!(d.due_now(1_000));
        assert!(d.due_now(2_000));
        assert!(!d.due_now(999));
        let off = Digest { enabled: false, ..d.clone() };
        assert!(!off.due_now(2_000));

        let v = d.to_json();
        assert_eq!(v["enabled"], true);
        assert!(v["due"].as_str().unwrap().ends_with("Z"));
        assert!(v["last_sent"].is_null());
        assert_eq!(v["urgency"], "normal");
        assert!(v["text"].as_str().unwrap().starts_with("moat: 0 needed you"));
        assert_eq!(v["needs_you"], 0);
        assert_eq!(v["recorded"], 0);
        assert_eq!(v["suppressed"], 0);
    }
}
