//! The resolved end-user identity for one request. Produced by the auth layer
//! (from a verified STS session token or a static credential), stashed in the s3s
//! request extensions by `S3Access::check`, and read by the typed hooks (for the OPA
//! input) and the S3 dispatcher (for backend routing). Always the **end-user**
//! identity — never a shared/service principal.

use crate::authz::{Principal, PrincipalAttributes};
use crate::model::{PrincipalType, Tenant};

#[derive(Debug, Clone)]
pub struct ResolvedPrincipal {
    pub sub: String,
    pub principal_type: PrincipalType,
    pub groups: Vec<String>,
    pub tenant: String,
    pub organization_id: String,
}

impl ResolvedPrincipal {
    pub fn tenant(&self) -> Tenant {
        Tenant(self.tenant.clone())
    }

    /// The principal half of the OPA input.
    pub fn to_opa_principal(&self) -> Principal {
        Principal {
            sub: self.sub.clone(),
            kind: self.principal_type,
            attributes: PrincipalAttributes {
                groups: self.groups.clone(),
                extra: serde_json::Map::new(),
            },
        }
    }
}
