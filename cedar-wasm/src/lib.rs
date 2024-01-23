#![forbid(unsafe_code)]

use wasm_bindgen::prelude::wasm_bindgen;

use cedar_policy::{
    Authorizer, Context, Entities, EntityUid, Policy, PolicySet, Request, Schema, ValidationMode,
    Validator,
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
    let principal = match EntityUid::from_str(principal_str) {
        Ok(principal) => principal,
        Err(err) => {
            return json!({
                "code": 101,
                "message": format!("[PrincipalErr]: {}", err),
            })
            .to_string();
        }
    };

    let action = match EntityUid::from_str(action_str) {
        Ok(action) => action,
        Err(err) => {
            return json!({
                "code": 102,
                "message": format!("[ActionErr]: {}", err),
            })
            .to_string();
        }
    };

    let resource = match EntityUid::from_str(resource_str) {
        Ok(resource) => resource,
        Err(err) => {
            return json!({
                "code": 103,
                "message": format!("[ResourceErr]: {}", err),
            })
            .to_string();
        }
    };

    let context = match Context::from_json_str(context_str, None) {
        Ok(context) => context,
        Err(err) => {
            return json!({
                "code": 104,
                "message": format!("[ContextErr]: {}", err),
            })
            .to_string();
        }
    };

    let policies = match PolicySet::from_str(policies_str) {
        Ok(policies) => policies,
        Err(err) => {
            return json!({
                "code": 105,
                "message": format!("[PoliciesErr]: {}", err),
            })
            .to_string();
        }
    };

    let entities = match Entities::from_json_str(entities_str, None) {
        Ok(entities) => entities,
        Err(err) => {
            return json!({
                "code": 106,
                "message": format!("[EntitiesErr]: {}", err),
            })
            .to_string();
        }
    };

    let request =
        Request::new(Some(principal), Some(action), Some(resource), context, None).unwrap();

    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&request, &policies, &entities);

    // change response to string
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
        "code": 0,
        "data": {
            "decision": decision,
            "reasons": reasons,
            "errors": errors,
        }
    })
    .to_string()
}

#[wasm_bindgen(js_name = "validate")]
pub fn validate(schema_str: &str, policy_str: &str) -> String {
    let schema = match Schema::from_str(schema_str) {
        Ok(schema) => schema,
        Err(err) => {
            return json!({
                "code": 201,
                "message": format!("[SchemaErr]: {}", err),
            })
            .to_string();
        }
    };

    let policy = match PolicySet::from_str(policy_str) {
        Ok(policy) => policy,
        Err(err) => {
            return json!({
                "code": 202,
                "message": format!("[PolicyErr]: {}", err),
            })
            .to_string();
        }
    };

    let validator = Validator::new(schema);

    let result = validator.validate(&policy, ValidationMode::default());

    json!({
        "code": 0,
        "data": format!("{}", result),
    })
    .to_string()
}

#[wasm_bindgen(js_name = "policyToJson")]
pub fn policy_to_json(policy_str: &str) -> String {
    let policy = match Policy::from_str(policy_str) {
        Ok(policy) => policy,
        Err(err) => {
            return json!({
                "code": 301,
                "message": format!("[PolicyErr]: {}", err),
            })
            .to_string();
        }
    };

    let policy_json = policy.to_json().unwrap();

    json!({
        "code": 0,
        "data": policy_json,
    })
    .to_string()
}

#[wasm_bindgen(js_name = "policyFromJson")]
pub fn policy_from_json(policy_str: &str) -> String {
    let policy_json = match serde_json::from_str(policy_str) {
        Ok(policy_json) => policy_json,
        Err(err) => {
            return json!({
                "code": 401,
                "message": format!("[PolicyJsonErr]: {}", err),
            })
            .to_string();
        }
    };

    let policy = match Policy::from_json(None, policy_json) {
        Ok(policy) => policy,
        Err(err) => {
            return json!({
                "code": 402,
                "message": format!("[PolicyErr]: {}", err),
            })
            .to_string();
        }
    };

    json!({
        "code": 0,
        "data": policy.to_string(),
    })
    .to_string()
}

#[wasm_bindgen(js_name = "validateSchema")]
pub fn validate_schema(schema_str: &str) -> String {
    match Schema::from_str(schema_str) {
        Ok(_) => {
            return json!({
                "code": 0,
                "data": "no errors or warnings",
            })
            .to_string();
        }
        Err(err) => {
            return json!({
                "code": 501,
                "message": format!("[SchemaErr]: {}", err),
            })
            .to_string();
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cedar_version() {
        let version = get_cedar_version();
        assert_eq!(version, std::env!("CEDAR_VERSION").to_string());
    }

    #[test]
    fn test_is_authorized() {
        let principal = r#"User::"alice""#;
        let action = r#"Action::"read""#;
        let resource = r#"Photo::"foo.jpg""#;
        let context = r#"{}"#;
        let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
        let entities = r#"[]"#;

        let result = is_authorized(principal, action, resource, context, policies, entities);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        let data = json["data"].clone();

        assert_eq!(json["code"], 0);
        assert_eq!(data["decision"], "Allow");
        assert_eq!(data["reasons"], serde_json::json!(["policy0"]));
        assert_eq!(data["errors"], serde_json::json!([]));
    }

    #[test]
    fn test_is_authorized_principal_err() {
        let principal = r#"User:"alice""#;
        let action = r#"Action::"read""#;
        let resource = r#"Photo::"foo.jpg""#;
        let context = r#"{}"#;
        let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
        let entities = r#"[]"#;

        let result = is_authorized(principal, action, resource, context, policies, entities);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 101);
        assert_eq!(json["message"], "[PrincipalErr]: unexpected token `:`");
    }

    #[test]
    fn test_is_authorized_action_err() {
        let principal = r#"User::"alice""#;
        let action = r#"Action:"read""#;
        let resource = r#"Photo::"foo.jpg""#;
        let context = r#"{}"#;
        let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
        let entities = r#"[]"#;

        let result = is_authorized(principal, action, resource, context, policies, entities);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 102);
        assert_eq!(json["message"], "[ActionErr]: unexpected token `:`");
    }

    #[test]
    fn test_is_authorized_resource_err() {
        let principal = r#"User::"alice""#;
        let action = r#"Action::"read""#;
        let resource = r#"Photo:"foo.jpg""#;
        let context = r#"{}"#;
        let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
        let entities = r#"[]"#;

        let result = is_authorized(principal, action, resource, context, policies, entities);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 103);
        assert_eq!(json["message"], "[ResourceErr]: unexpected token `:`");
    }

    #[test]
    fn test_is_authorized_context_err() {
        let principal = r#"User::"alice""#;
        let action = r#"Action::"read""#;
        let resource = r#"Photo::"foo.jpg""#;
        let context = r#"[]"#;
        let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
        let entities = r#"[]"#;

        let result = is_authorized(principal, action, resource, context, policies, entities);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 104);
        assert_eq!(
            json["message"],
            "[ContextErr]: expression is not a record: `[]`"
        );
    }

    #[test]
    fn test_is_authorized_policies_err() {
        let principal = r#"User::"alice""#;
        let action = r#"Action::"read""#;
        let resource = r#"Photo::"foo.jpg""#;
        let context = r#"{}"#;
        let policies = r#"
            permit(
                principal == User:"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
        let entities = r#"[]"#;

        let result = is_authorized(principal, action, resource, context, policies, entities);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 105);
        assert_eq!(json["message"], "[PoliciesErr]: unexpected token `:`");
    }

    #[test]
    fn test_is_authorized_entities_err() {
        let principal = r#"User::"alice""#;
        let action = r#"Action::"read""#;
        let resource = r#"Photo::"foo.jpg""#;
        let context = r#"{}"#;
        let policies = r#"
            permit(
                principal == User::"alice",
                action    in [Action::"read", Action::"edit"],
                resource  == Photo::"foo.jpg"
            );
        "#;
        let entities = r#"{}"#;

        let result = is_authorized(principal, action, resource, context, policies, entities);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 106);
        assert_eq!(json["message"], "[EntitiesErr]: error during entity deserialization: invalid type: map, expected a sequence at line 1 column 0");
    }

    #[test]
    fn test_validate_ok() {
        let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
        let policy = r#"
            permit(
                principal in PhotoApp::UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

        let result = validate(schema, policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 0);
        assert_eq!(json["data"], "no errors or warnings");
    }

    #[test]
    fn test_validate_fail() {
        let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
        let policy = r#"
            permit(
                principal in PhotoApp::UserGroup1::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

        let result = validate(schema, policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 0);
        assert_eq!(
            json["data"],
            "validation error on policy `policy0`: unrecognized entity type `PhotoApp::UserGroup1`"
        );
    }

    #[test]
    fn test_validate_schema_json_err() {
        let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        }
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
        let policy = r#"
            permit(
                principal in PhotoApp::UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"],
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

        let result = validate(schema, policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 201);
        assert_eq!(
            json["message"],
            "[SchemaErr]: failed to parse schema: expected `,` or `}` at line 16 column 25"
        );
    }

    #[test]
    fn test_validate_on_schema_err() {
        let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
        let policy = r#"
            permit(
                principal in PhotoApp::UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

        let result = validate(schema, policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 201);
        assert_eq!(
            json["message"],
            "[SchemaErr]: failed to parse schema: missing field `type` at line 14 column 25"
        );
    }

    #[test]
    fn test_validate_policy_err() {
        let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;
        let policy = r#"
            permit(
                principal in PhotoApp:UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

        let result = validate(schema, policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 202);
        assert_eq!(json["message"], "[PolicyErr]: unexpected token `:`");
    }

    #[test]
    fn test_policy_to_json() {
        let policy = r#"
            permit(
                principal in PhotoApp::UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

        let result = policy_to_json(policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 0);
        assert_eq!(
            json["data"].to_string(),
            "{\"effect\":\"permit\",\"principal\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::UserGroup\",\"id\":\"janeFriends\"}},\"action\":{\"op\":\"in\",\"entities\":[{\"type\":\"PhotoApp::Action\",\"id\":\"viewPhoto\"},{\"type\":\"PhotoApp::Action\",\"id\":\"listPhotos\"}]},\"resource\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::Album\",\"id\":\"janeTrips\"}},\"conditions\":[]}"
        );
    }

    #[test]
    fn test_policy_to_json_err() {
        let policy = r#"
            permit(
                principal in PhotoApp:UserGroup::"janeFriends",
                action in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"], 
                resource in PhotoApp::Album::"janeTrips"
            );
        "#;

        let result = policy_to_json(policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 301);
        assert_eq!(json["message"], "[PolicyErr]: unexpected token `:`");
    }

    #[test]
    fn test_policy_from_json() {
        let policy = "{\"effect\":\"permit\",\"principal\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::UserGroup\",\"id\":\"janeFriends\"}},\"action\":{\"op\":\"in\",\"entities\":[{\"type\":\"PhotoApp::Action\",\"id\":\"viewPhoto\"},{\"type\":\"PhotoApp::Action\",\"id\":\"listPhotos\"}]},\"resource\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::Album\",\"id\":\"janeTrips\"}},\"conditions\":[]}";

        let result = policy_from_json(policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 0);
        assert_eq!(
            json["data"].to_string(),
            "\"permit(principal in PhotoApp::UserGroup::\\\"janeFriends\\\", action in [PhotoApp::Action::\\\"viewPhoto\\\", PhotoApp::Action::\\\"listPhotos\\\"], resource in PhotoApp::Album::\\\"janeTrips\\\");\""
        );
    }

    #[test]
    fn test_policy_from_json_policy_json_err() {
        let policy = "{\"effect\"\"permit\",\"principal\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::UserGroup\",\"id\":\"janeFriends\"}},\"action\":{\"op\":\"in\",\"entities\":[{\"type\":\"PhotoApp::Action\",\"id\":\"viewPhoto\"},{\"type\":\"PhotoApp::Action\",\"id\":\"listPhotos\"}]},\"resource\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::Album\",\"id\":\"janeTrips\"}},\"conditions\":[]}";

        let result = policy_from_json(policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 401);
        assert_eq!(
            json["message"],
            "[PolicyJsonErr]: expected `:` at line 1 column 10"
        );
    }

    #[test]
    fn test_policy_from_json_policy_err() {
        let policy = "{\"principal\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::UserGroup\",\"id\":\"janeFriends\"}},\"action\":{\"op\":\"in\",\"entities\":[{\"type\":\"PhotoApp::Action\",\"id\":\"viewPhoto\"},{\"type\":\"PhotoApp::Action\",\"id\":\"listPhotos\"}]},\"resource\":{\"op\":\"in\",\"entity\":{\"type\":\"PhotoApp::Album\",\"id\":\"janeTrips\"}},\"conditions\":[]}";

        let result = policy_from_json(policy);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 402);
        assert_eq!(json["message"], "[PolicyErr]: missing field `effect`");
    }

    #[test]
    fn test_validate_schema_ok() {
        let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        },
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;

        let result = validate_schema(schema);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 0);
        assert_eq!(json["data"], "no errors or warnings");
    }

    #[test]
    fn test_validate_schema_err() {
        let schema = r#"
            {
                "PhotoApp": {
                    "commonTypes": {
                        "PersonType": {
                            "type": "Record",
                            "attributes": {
                                "age": {
                                    "type": "Long"
                                },
                                "name": {
                                    "type": "String"
                                }
                            }
                        }
                        "ContextType": {
                            "type": "Record",
                            "attributes": {
                                "ip": {
                                    "type": "Extension",
                                    "name": "ipaddr"
                                }
                            }
                        }
                    },
                    "entityTypes": {
                        "User": {
                            "shape": {
                                "type": "Record",
                                "attributes": {
                                    "employeeId": {
                                        "type": "String",
                                        "required": true
                                    },
                                    "personInfo": {
                                        "type": "PersonType"
                                    }
                                }
                            },
                            "memberOfTypes": [
                                "UserGroup"
                            ]
                        },
                        "UserGroup": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        },
                        "Photo": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            },
                            "memberOfTypes": [
                                "Album"
                            ]
                        },
                        "Album": {
                            "shape": {
                                "type": "Record",
                                "attributes": {}
                            }
                        }
                    },
                    "actions": {
                        "viewPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "createPhoto": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        },
                        "listPhotos": {
                            "appliesTo": {
                                "principalTypes": [
                                    "User",
                                    "UserGroup"
                                ],
                                "resourceTypes": [
                                    "Photo"
                                ],
                                "context": {
                                    "type": "ContextType"
                                }
                            }
                        }
                    }
                }
            }
        "#;

        let result = validate_schema(schema);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["code"], 501);
        assert_eq!(
            json["message"],
            "[SchemaErr]: failed to parse schema: expected `,` or `}` at line 16 column 25"
        );
    }
}
