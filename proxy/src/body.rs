//! Request bodies in flight.
//!
//! An upload used to be read into memory whole before anything was sent
//! upstream, which capped it at `max_request_body_mb` and meant a large one
//! simply failed. Now both front ends push the body into a bounded channel as
//! it arrives, and the worker on the other end decides what to do with it:
//! drain it into memory when an interceptor asked for it, or hand it to the
//! upstream client and let it flow through.
//!
//! One channel type for both front ends, which is why it is tokio's rather than
//! the standard library's: the TCP side produces from async and wants to await
//! a full channel, the QUIC side produces from a single-threaded event loop
//! that must never block and so uses `try_send`, and the consumer is a plain
//! worker thread using [`Receiver::blocking_recv`]. Only tokio's channel serves
//! all three.
//!
//! The channel is the backpressure. A worker that stops reading — because it is
//! talking to a slow origin — fills the channel, and the front end stops taking
//! body bytes off the client.

use std::io::Read;

use tokio::sync::mpsc::{Receiver, Sender};

/// One piece of an upload, as it came off the wire.
pub type Chunk = Vec<u8>;

/// How many chunks may sit between the front end and the worker. Chunks are
/// whatever the transport handed us, so this is a bound on count rather than
/// bytes; the QUIC side additionally bounds what it parks when this is full.
const CHANNEL_DEPTH: usize = 16;

pub fn channel() -> (Sender<Chunk>, Receiver<Chunk>) {
	tokio::sync::mpsc::channel(CHANNEL_DEPTH)
}

/// The body of a request being forwarded, from the worker's point of view.
pub enum RequestBody {
	/// Nothing to send: no body, or one already read into `ProxyRequest::body`.
	None,
	/// Bytes still arriving. `length` is what the client said it was sending,
	/// when it said — passing it on lets the upstream request use the same
	/// framing the client used rather than falling back to chunked, which some
	/// origins refuse.
	Streaming {
		reader: Reader,
		length: Option<u64>,
	},
}

/// A [`Read`] over the chunks a front end is feeding us.
///
/// Blocking is the point: the worker thread is already blocked on the upstream
/// client, and reading the next chunk is exactly as long as it should wait.
pub struct Reader {
	chunks: Receiver<Chunk>,
	/// What is left of the chunk last handed out, since a caller's buffer is
	/// rarely the same size as a chunk.
	rest: Chunk,
	offset: usize,
}

impl Reader {
	pub fn new(chunks: Receiver<Chunk>) -> Self {
		Self {
			chunks,
			rest: Vec::new(),
			offset: 0,
		}
	}
}

impl Read for Reader {
	fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
		if self.offset == self.rest.len() {
			// The sender being dropped is how a front end says "that was all of
			// it", so it ends the body rather than failing it.
			let Some(chunk) = self.chunks.blocking_recv() else {
				return Ok(0);
			};

			self.rest = chunk;
			self.offset = 0;
		}

		let take = (self.rest.len() - self.offset).min(out.len());
		out[..take].copy_from_slice(&self.rest[self.offset..self.offset + take]);
		self.offset += take;

		Ok(take)
	}
}

/// Read the whole body into memory, refusing past `cap`.
///
/// This is what happens when an interceptor asked to see the body: the cap
/// still applies, because holding an upload in memory is exactly the thing it
/// exists to bound. Streaming is what removed the limit, not this.
pub fn read_to_cap(reader: &mut impl Read, cap: usize) -> Result<Vec<u8>, TooLarge> {
	let mut body = Vec::new();
	let mut buf = [0u8; 64 * 1024];

	loop {
		let read = match reader.read(&mut buf) {
			Ok(0) => return Ok(body),
			Ok(n) => n,
			// A client that goes away mid-upload leaves us with a partial body;
			// forwarding it is worse than treating it as the failure it is.
			Err(e) => return Err(TooLarge::Interrupted(e)),
		};

		if body.len() + read > cap {
			return Err(TooLarge::Cap);
		}

		body.extend_from_slice(&buf[..read]);
	}
}

pub enum TooLarge {
	Cap,
	Interrupted(std::io::Error),
}

#[cfg(test)]
mod tests {
	use super::*;

	fn reader_of(chunks: &[&[u8]]) -> Reader {
		let (tx, rx) = channel();
		for chunk in chunks {
			tx.try_send(chunk.to_vec()).expect("channel has room");
		}
		drop(tx);

		Reader::new(rx)
	}

	#[test]
	fn chunks_arrive_as_one_stream() {
		let mut reader = reader_of(&[b"hello ", b"streaming ", b"world"]);
		let mut got = String::new();
		reader.read_to_string(&mut got).unwrap();

		assert_eq!(got, "hello streaming world");
	}

	#[test]
	fn a_chunk_larger_than_the_buffer_is_handed_out_in_pieces() {
		let mut reader = reader_of(&[b"abcdefghij"]);
		let mut buf = [0u8; 4];

		assert_eq!(reader.read(&mut buf).unwrap(), 4);
		assert_eq!(&buf, b"abcd");
		assert_eq!(reader.read(&mut buf).unwrap(), 4);
		assert_eq!(&buf, b"efgh");
		assert_eq!(reader.read(&mut buf).unwrap(), 2);
		assert_eq!(&buf[..2], b"ij");
		assert_eq!(reader.read(&mut buf).unwrap(), 0, "then end of body");
	}

	#[test]
	fn a_dropped_sender_ends_the_body() {
		let (tx, rx) = channel();
		drop(tx);

		let mut reader = Reader::new(rx);
		let mut got = Vec::new();
		reader.read_to_end(&mut got).unwrap();

		assert!(got.is_empty(), "no chunks means an empty body, not an error");
	}

	#[test]
	fn reading_to_cap_stops_at_the_cap() {
		let mut reader = reader_of(&[b"0123456789", b"0123456789"]);

		assert!(matches!(read_to_cap(&mut reader, 15), Err(TooLarge::Cap)));
	}

	#[test]
	fn reading_to_cap_accepts_exactly_the_cap() {
		let mut reader = reader_of(&[b"0123456789", b"0123456789"]);

		assert_eq!(read_to_cap(&mut reader, 20).ok().map(|b| b.len()), Some(20));
	}
}
