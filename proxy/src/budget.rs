//! Backpressure for one h3 response.
//!
//! The TCP front end gets this for free: each response has its own bounded
//! channel, and a worker filling it faster than the client drains it simply
//! parks. The QUIC front end cannot copy that. It has one results channel
//! shared by every stream of every connection, so bounding *it* would park a
//! worker holding a chunk for a slow client behind chunks meant for everybody
//! else — head-of-line blocking across unrelated connections, which is worse
//! than the problem.
//!
//! So the bound is per stream. A worker claims room before it hands a chunk
//! over, and the event loop gives that room back as the bytes reach quiche.
//! Without it, a client that stops reading — a phone that went into a tunnel
//! mid-download — leaves the worker reading the origin at full speed into a
//! queue nothing is draining, and the only limit is the size of the file.

use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// How long a worker will wait for a client that is making no progress at all
/// before giving up on the stream.
///
/// Not a bandwidth floor: any byte reaching quiche frees room and resets this,
/// so a phone on a bad connection keeps its download. What it bounds is the
/// other case — a client that has stopped reading entirely, whose stream quiche
/// will hold open until its idle timeout. Without this the worker is held for
/// that long too, and a handful of abandoned downloads is enough to occupy
/// every worker there is.
const STALLED: Duration = Duration::from_secs(10);

/// How much of one response may sit between the worker that fetched it and the
/// client that has not read it yet.
pub struct Budget {
	state: Mutex<State>,
	room: Condvar,
	limit: usize,
	stalled: Duration,
}

struct State {
	outstanding: usize,
	/// Bumped every time room is given back. The stall window is measured
	/// against *this*, not against the clock, so a client that is merely slow
	/// keeps resetting it and only one that has stopped entirely runs it out.
	progress: u64,
	/// Set when nothing will drain this stream again — the client went away, or
	/// its stream failed. A worker parked on it has to be let go, or it holds a
	/// pool thread for the lifetime of the process.
	closed: bool,
}

impl Budget {
	pub fn new(limit: usize) -> Self {
		Self::with_stall(limit, STALLED)
	}

	/// The window is a parameter only so the tests do not have to take ten
	/// seconds to prove it exists.
	fn with_stall(limit: usize, stalled: Duration) -> Self {
		Self {
			state: Mutex::new(State {
				outstanding: 0,
				progress: 0,
				closed: false,
			}),
			room: Condvar::new(),
			limit,
			stalled,
		}
	}

	/// Park until there is room for `bytes`, then take it.
	///
	/// `false` means the stream is gone and the caller should stop reading the
	/// origin: nothing it produces from here can reach anyone.
	pub fn claim(&self, bytes: usize) -> bool {
		let mut state = self.state.lock().expect("budget lock");

		// The wait is on the queue being *empty*, not on the chunk fitting. A
		// chunk larger than the whole allowance still has to go somewhere, and
		// waiting for it to fit would deadlock a stream whose limit is smaller
		// than one read from the origin. Nothing is ever queued behind a chunk
		// that overshoots, which is the property that matters.
		let full = |state: &State| state.outstanding > 0 && state.outstanding + bytes > self.limit;

		if full(&state) && !state.closed {
			// Counted once per park rather than once per wakeup: what is worth
			// knowing is how often a client could not keep up, not how many
			// times the condvar fired while it caught up.
			crate::metrics::shared().streams_parked.increment();
		}

		let mut seen = state.progress;
		while !state.closed && full(&state) {
			let (waited, expiry) = self
				.room
				.wait_timeout(state, self.stalled)
				.expect("budget lock");
			state = waited;

			if state.progress != seen {
				// Bytes moved, so the client is slow rather than gone and the
				// window starts again. `wait_timeout` counts the whole wait,
				// not each wakeup, so this has to be tracked by hand.
				seen = state.progress;

				continue;
			}

			if expiry.timed_out() {
				// Nothing moved for the whole window, so nothing is going to.
				// Marked closed rather than merely refused, so a later claim
				// does not park for another window of its own.
				log::warn!(
					"giving up on a stream that took nothing for {}s; the client has stopped reading",
					self.stalled.as_secs()
				);
				state.closed = true;
			}
		}

		if state.closed {
			return false;
		}

		state.outstanding += bytes;

		true
	}

	/// Bytes have reached the client, or gone with the stream that wanted them.
	pub fn release(&self, bytes: usize) {
		let mut state = self.state.lock().expect("budget lock");
		state.outstanding = state.outstanding.saturating_sub(bytes);
		state.progress = state.progress.wrapping_add(1);
		// Woken rather than signalled: one worker waits per budget today, and
		// a missed wakeup here is a stalled response.
		self.room.notify_all();
	}

	/// Nobody will read this stream again. Idempotent, because both the stream
	/// failing and the connection closing can reach it.
	pub fn close(&self) {
		let mut state = self.state.lock().expect("budget lock");
		state.closed = true;
		self.room.notify_all();
	}

}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Arc;
	use std::time::Duration;

	/// Give a spawned thread a moment to get where it is going. Crude, but the
	/// alternative is instrumenting the condvar to test the condvar.
	fn settle() {
		std::thread::sleep(Duration::from_millis(50));
	}

	#[test]
	fn room_is_taken_and_given_back() {
		let budget = Budget::new(100);

		assert!(budget.claim(60));
		assert!(budget.claim(30));
		budget.release(60);
		assert!(budget.claim(60), "the released room is available again");
	}

	#[test]
	fn a_worker_parks_once_the_client_stops_reading() {
		let budget = Arc::new(Budget::new(100));
		assert!(budget.claim(100));

		let waiting = budget.clone();
		let done = Arc::new(AtomicUsize::new(0));
		let flag = done.clone();
		let worker = std::thread::spawn(move || {
			assert!(waiting.claim(50));
			flag.store(1, Ordering::SeqCst);
		});

		settle();
		assert_eq!(done.load(Ordering::SeqCst), 0, "it must not have got past");

		budget.release(100);
		worker.join().expect("the worker resumes");
		assert_eq!(done.load(Ordering::SeqCst), 1);
	}

	/// A parked worker that is never released holds a pool thread for the life
	/// of the process, and there are only as many threads as cores.
	#[test]
	fn closing_releases_a_parked_worker() {
		let budget = Arc::new(Budget::new(100));
		assert!(budget.claim(100));

		let waiting = budget.clone();
		let worker = std::thread::spawn(move || waiting.claim(50));

		settle();
		budget.close();

		assert!(
			!worker.join().expect("the worker resumes"),
			"and it is told not to bother reading any more"
		);
		assert!(!budget.claim(1), "a closed budget stays closed");
	}

	/// A client that has stopped reading altogether still has a stream quiche
	/// will hold open until its idle timeout. The worker behind it must not be
	/// held that long: there are only as many workers as cores, and a handful
	/// of abandoned downloads would occupy every one of them.
	#[test]
	fn a_worker_gives_up_on_a_client_that_never_moves() {
		let window = Duration::from_millis(150);
		let budget = Budget::with_stall(100, window);
		assert!(budget.claim(100));

		let started = std::time::Instant::now();
		assert!(!budget.claim(50), "it gives up rather than waiting forever");
		assert!(started.elapsed() >= window, "and only after the whole window");
		assert!(!budget.claim(1), "the stream stays given up on");
	}

	/// The window is about a client making *no* progress. One that is merely
	/// slow keeps its download for as long as it keeps taking bytes.
	#[test]
	fn a_slow_client_is_not_a_stalled_one() {
		let window = Duration::from_millis(150);
		let budget = Arc::new(Budget::with_stall(100, window));
		assert!(budget.claim(100));

		let draining = budget.clone();
		let drain = std::thread::spawn(move || {
			for _ in 0..4 {
				std::thread::sleep(window / 2);
				draining.release(25);
			}
		});

		assert!(budget.claim(50), "it waited rather than giving up");
		drain.join().expect("the drain finishes");
	}

	/// The origin's chunk size is not the operator's to choose. A limit below
	/// it must slow the stream down, not stop it.
	#[test]
	fn a_chunk_bigger_than_the_whole_allowance_still_goes() {
		let budget = Budget::new(10);

		assert!(budget.claim(64 * 1024), "an empty queue always has room");
		budget.release(64 * 1024);
		assert!(budget.claim(64 * 1024));
	}
}
