#![forbid(unsafe_code)]

use wasm_bindgen::prelude::wasm_bindgen;

use cedar_policy::{
    Authorizer, Context, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode, Validator,
};

use serde_json::json;

use std::collections::HashSet;
use std::str::FromStr;

#[wasm_bindgen(js_name = "getCedarVersion")]
pub fn get_cedar_version() -> String {
    std::env!("CEDAR_VERSION").to_string()
}

#[wasm_bindgen(js_name = "isAuthorized")]
pub fn is_authorized(
    principal_str: &str,
    action_str: &str,
    resource_str: &str,
    context_str: &str,
    policies_str: &str,
    entities_str: &str,
) -> String {
    let principal = EntityUid::from_str(principal_str).expect("entity parse error");
    let action = EntityUid::from_str(action_str).expect("entity parse error");
    let resource = EntityUid::from_str(resource_str).expect("entity parse error");
    let context = Context::from_json_str(context_str, None).expect("entity parse error");

    let request =
        Request::new(Some(principal), Some(action), Some(resource), context, None).unwrap();
    let policy_set = PolicySet::from_str(policies_str).expect("entity parse error");
    let entities = Entities::from_json_str(entities_str, None).expect("entity parse error");

    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&request, &policy_set, &entities);

    let decision = response.decision();
    let diagnostics = response.diagnostics();

    let _reasons = diagnostics.reason();
    let mut reasons = HashSet::new();
    for reason in _reasons {
        reasons.insert(reason.to_string());
    }

    let _errors = diagnostics.errors();
    let mut errors = Vec::new();
    for err in _errors {
        let error = err.to_string();
        errors.push(error);
    }

    json!({
        "decision": decision,
        "reasons": reasons,
        "errors": errors,
    })
    .to_string()
}

#[wasm_bindgen(js_name = "validate")]
pub fn validate(schema_str: &str, policies_str: &str) -> String {
    let json = serde_json::from_str(schema_str).unwrap();
    let schema: Schema = Schema::from_json_value(json).unwrap();

    let validator = Validator::new(schema);

    let policy_set = PolicySet::from_str(policies_str).expect("entity parse error");

    let result = validator.validate(&policy_set, ValidationMode::default());

    result.to_string()
}
