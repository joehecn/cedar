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
    let principal = EntityUid::from_str(principal_str).expect("principal parse error");
    let action = EntityUid::from_str(action_str).expect("action parse error");
    let resource = EntityUid::from_str(resource_str).expect("resource parse error");
    let context = Context::from_json_str(context_str, None).expect("context parse error");
    let policies = PolicySet::from_str(policies_str).expect("policies parse error");
    let entities = Entities::from_json_str(entities_str, None).expect("entities parse error");

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
        "decision": decision,
        "reasons": reasons,
        "errors": errors,
    })
    .to_string()
}

#[wasm_bindgen(js_name = "validate")]
pub fn validate(schema_str: &str, policy_str: &str) -> String {
    let schema_json = serde_json::from_str(schema_str).expect("schema_json parse error");
    let schema: Schema = Schema::from_json_value(schema_json).expect("schema parse error");
    let policy = PolicySet::from_str(policy_str).expect("policy parse error");

    let validator = Validator::new(schema);

    let result = validator.validate(&policy, ValidationMode::default());

    result.to_string()
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

        assert_eq!(json["decision"], "Allow");
        assert_eq!(json["reasons"], serde_json::json!(["policy0"]));
        assert_eq!(json["errors"], serde_json::json!([]));
    }

    #[test]
    #[should_panic(expected = "principal parse error")]
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

        is_authorized(principal, action, resource, context, policies, entities);
    }

    #[test]
    #[should_panic(expected = "action parse error")]
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

        is_authorized(principal, action, resource, context, policies, entities);
    }

    #[test]
    #[should_panic(expected = "resource parse error")]
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

        is_authorized(principal, action, resource, context, policies, entities);
    }

    #[test]
    #[should_panic(expected = "context parse error")]
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

        is_authorized(principal, action, resource, context, policies, entities);
    }

    #[test]
    #[should_panic(expected = "policies parse error")]
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

        is_authorized(principal, action, resource, context, policies, entities);
    }

    #[test]
    #[should_panic(expected = "entities parse error")]
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

        is_authorized(principal, action, resource, context, policies, entities);
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

        assert_eq!(result, "no errors or warnings".to_string());
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
        println!("---- result:");
        println!("{}", result);
        println!("---- result:");

        assert_eq!(
            result,
            "validation error on policy `policy0`: unrecognized entity type `PhotoApp::UserGroup1`"
                .to_string()
        );
    }

    #[test]
    #[should_panic(expected = "schema_json parse error")]
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

        assert_eq!(result, "no errors or warnings".to_string());
    }

    #[test]
    #[should_panic(expected = "schema parse error")]
    fn test_validate_schema_err() {
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

        assert_eq!(result, "no errors or warnings".to_string());
    }

    #[test]
    #[should_panic(expected = "policy parse error")]
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

        assert_eq!(result, "no errors or warnings".to_string());
    }
}
