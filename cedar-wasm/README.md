# cedar-wasm

An implementation of various cedar functions to enable developers to write typescript and javascript applications using Cedar and wasm.

## nodejs
```bash
npm i @joehecnnodejs/cedar-wasm
```
```js
import { getCedarVersion, isAuthorized, validate } from "@joehecnnodejs/cedar-wasm";
```

## web
```bash
npm i @joehecnweb/cedar-wasm
```
```js
import { getCedarVersion, isAuthorized, validate } from '@joehecnweb/cedar-wasm'
```

## vite
See [vite-plugin-wasm](https://github.com/Menci/vite-plugin-wasm)

## example
```js
...
/* getCedarVersion */
const version = getCedarVersion()
// { version: '3.0.0' }
console.log({ version })

/* isAuthorized */
const principal = 'User::"alice"'
const action = 'Action::"read"'
const resource = 'Photo::"foo.jpg"'
const context = '{}'
const policies = `
    permit(
      principal == User::"alice",
      action    in [Action::"read", Action::"edit"],
      resource  == Photo::"foo.jpg"
    );
  `
const entities = '[]'
const result = isAuthorized(principal, action, resource, context, policies, entities)
// { code: 0, data: { decision: 'Allow', reasons: [ 'policy0' ], errors: [] } }
console.log(JSON.parse(result))

/* validate */
const schema = JSON.stringify({
  PhotoApp: {
    commonTypes: {
      PersonType: {
        type: 'Record',
        attributes: {
          age: {
            type: 'Long'
          },
          name: {
            type: 'String'
          }
        }
      },
      ContextType: {
        type: 'Record',
        attributes: {
          ip: {
            type: 'Extension',
            name: 'ipaddr'
          }
        }
      }
    },
    entityTypes: {
      User: {
        shape: {
          type: 'Record',
          attributes: {
            employeeId: {
              type: 'String',
              required: true
            },
            personInfo: {
              type: 'PersonType'
            }
          }
        },
        memberOfTypes: ['UserGroup']
      },
      UserGroup: {
        shape: {
          type: 'Record',
          attributes: {}
        }
      },
      Photo: {
        shape: {
          type: 'Record',
          attributes: {}
        },
        memberOfTypes: ['Album']
      },
      Album: {
        shape: {
          type: 'Record',
          attributes: {}
        }
      }
    },
    actions: {
      viewPhoto: {
        appliesTo: {
          principalTypes: ['User', 'UserGroup'],
          resourceTypes: ['Photo'],
          context: {
            type: 'ContextType'
          }
        }
      },
      createPhoto: {
        appliesTo: {
          principalTypes: ['User', 'UserGroup'],
          resourceTypes: ['Photo'],
          context: {
            type: 'ContextType'
          }
        }
      },
      listPhotos: {
        appliesTo: {
          principalTypes: ['User', 'UserGroup'],
          resourceTypes: ['Photo'],
          context: {
            type: 'ContextType'
          }
        }
      }
    }
  }
})
const policie = `
    permit(
      principal in PhotoApp::UserGroup::"janeFriends",
      action    in [PhotoApp::Action::"viewPhoto", PhotoApp::Action::"listPhotos"],
      resource  in PhotoApp::Album::"janeTrips"
    );
  `
const validationResult = validate(schema, policie)
// { validationResult: 'no errors or warnings' }
console.log({ validationResult })
```
