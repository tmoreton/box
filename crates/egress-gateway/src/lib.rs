//! Outbound enforcement for the Strands box.

#![warn(missing_docs, unreachable_pub)]

mod audit;
mod boundary;
mod capability;
mod effect;
mod error;
mod intercept;
mod mcp;
mod seams;

pub use audit::{Decision as AuditDecision, EgressDecision, RequestId};
pub use boundary::{
    HeaderMap, InterceptedRequest, InterceptedResponse, Mutation, MutationTarget, Target,
};
pub use capability::{CapabilitySet, CredentialCapability, is_bindable_host, normalize_host};
pub use effect::{
    EffectAttempt, EffectInterceptor, EffectOutcome, EffectPermit, McpFrame, McpListReply,
};
pub use error::{PROXY_ORIGIN_HEADER, PROXY_ORIGIN_VALUE, ProxyError, Result};
pub use mcp::{
    McpTarget, McpTargetIdentity, canonicalize_mcp_frame, mcp_denial_response,
    refuse_duplicate_mcp_keys,
};
pub use seams::{Emitter, StubEmitter};

#[cfg(feature = "tls-intercept")]
pub use intercept::{MitmConfig, MitmHandle, MitmInterceptor, ResponseLimits};
