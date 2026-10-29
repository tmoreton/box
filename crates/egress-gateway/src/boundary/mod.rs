//! The messages the gateway reads and edits: a request, its response, and the edits.

mod request;
mod response;
mod verdict;

pub use request::{HeaderMap, InterceptedRequest, Target};
pub use response::InterceptedResponse;
pub(crate) use verdict::hex_value;
pub use verdict::{Mutation, MutationTarget};
