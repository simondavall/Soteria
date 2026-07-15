# Actors and responsibilities

## User

The human using the consuming web application.

### Responsibilities

- Initiates sign-in from the consuming application.
- Authenticates through Soteria.
- Completes any required Identity workflows, such as two-factor authentication or account confirmation.
- May grant consent if Soteria requires consent for the requested client and scopes.

The user does not provide Soteria credentials to the consuming application or the resource API.

## Browser

The user agent carrying the interactive authentication flow.

### Responsibilities

- Follows redirects between the consuming application and Soteria.
- Carries Soteria’s local authentication cookie when interacting with Soteria.
- Carries the consuming application’s local session cookie when interacting with that application.
- Returns the authorization response to the consuming application.

The browser does not make protocol trust decisions and should not need direct access to the API access token in the preferred server-side model.

## Consuming web application

The OpenID Connect client through which the user accesses application functionality.

For Phase 2, this will be the reference web application.

### Responsibilities

- Detects that the user does not have a local authenticated session.
- Starts an OpenID Connect authorization request.
- Redirects the browser to Soteria.
- Receives the authorization response.
- Exchanges the authorization code for tokens.
- Validates the OpenID Connect response through its authentication middleware.
- Creates and manages its own local session.
- Stores or otherwise manages the access token securely.
- Attaches the access token to outbound API requests.
- Applies its own UI and business-level authorization rules.

The consuming application must not:

- collect Soteria credentials;
- use Soteria’s authentication cookie as its own;
- query Soteria’s database directly;
- send the ID token to the resource API as an API credential;
- treat the access token as proof that every application operation is permitted.

## Soteria

The OpenID Connect Provider and OAuth authorization server.

Soteria is the overall security authority coordinating Identity, OpenIddict, client registrations, scopes, claims, and future application access rules.

## Responsibilities

- Hosts user-facing authentication workflows.
- Maintains the user’s local Soteria session.
- Receives OpenID Connect and OAuth requests.
- Coordinates user authentication with ASP.NET Core Identity.
- Determines whether the client is permitted to request the flow.
- Determines whether consent is required.
- Determines which scopes may be granted.
- Determines which claims may be issued.
- Determines the intended resource audiences for access tokens.
- Supplies the authenticated principal and authorization decisions to OpenIddict.
- Acts as the source of truth for future client access, roles, and application-specific claims.

Soteria owns the policy decisions even when framework components perform the protocol mechanics.

## ASP.NET Core Identity

Soteria’s local user account and interactive authentication system.

### Responsibilities

- Stores users and credential-related account data.
- Verifies passwords.
- Handles email confirmation.
- Handles password reset and recovery.
- Handles lockout.
- Handles two-factor authentication.
- Creates and validates Soteria’s local authentication cookie.
- Provides the authenticated user principal to the Soteria authorization workflow.

Identity answers:

- Has this user authenticated successfully to Soteria?

Identity does not:

- validate client registrations;
- validate redirect URIs;
- issue authorization codes;
- issue OpenID Connect or OAuth tokens;
- decide API audiences;
- decide which client receives which claims.

## OpenIddict

The framework implementing the OpenID Connect and OAuth protocol behaviour within Soteria.

### Responsibilities

- Validates authorization requests.
- Validates token requests.
- Validates client identifiers, redirect URIs, endpoint permissions, grant types, response types, scopes, and PKCE parameters.
- Generates authorization codes.
- Issues ID tokens.
- Issues access tokens.
- Publishes discovery metadata and signing-key information.
- Signs and protects protocol artifacts.
- Enforces token lifetimes and configured protocol rules.

OpenIddict answers:

- Is this protocol request valid, and what protocol response should be generated from the identity and authorization information supplied by Soteria?

OpenIddict does not verify the user’s password or define Soteria’s business authorization policy.

## Resource API

The third system that exposes protected data or operations.

In OAuth terminology, this is the resource server.

### Responsibilities

- Receives API requests carrying bearer access tokens.
- Validates that the token was issued by Soteria.
- Validates the token signature.
- Validates token expiry and other applicable time constraints.
- Validates the issuer.
- Validates that the token is intended for this API.
- Evaluates required scopes and claims.
- Applies its own endpoint and business authorization rules.
- Returns data or rejects the request.

The resource API must not:

- accept the consuming application’s session cookie;
- accept an ID token in place of an access token;
- query Soteria’s Identity or OpenIddict tables directly;
- assume a valid token automatically grants access to every endpoint.

## Database

The persistence mechanism used by Soteria.

### Responsibilities

Likely ASP.NET Core Identity data:

- users;
- credentials and security metadata;
- Identity roles;
- Identity claims;
- external login records;
- Identity token data.

Likely OpenIddict data:

- client registrations;
- authorizations;
- scopes;
- tokens.

Future Soteria data:

- application access assignments;
- application-specific roles;
- application-specific claims;
- client administration metadata.

Only Soteria accesses this database directly. The consuming application and resource API rely on protocol messages and tokens instead.

# Complete Conceptual Flow
```
User
  │
  │ Opens protected application functionality
  ▼
Consuming web application
  │
  │ Redirects browser with an authorization request
  ▼
Soteria / OpenIddict
  │
  │ Determines whether the user must authenticate
  ▼
ASP.NET Core Identity
  │
  │ Authenticates the user and establishes Soteria's local session
  ▼
Soteria
  │
  │ Determines permitted scopes, claims and API audiences
  ▼
OpenIddict
  │
  │ Issues an authorization code
  ▼
Consuming web application
  │
  │ Exchanges the code using PKCE
  ▼
OpenIddict
  │
  ├── Issues an ID token for the consuming application
  └── Issues an access token for the resource API
          │
          ▼
Consuming web application
  │
  │ Creates its local session
  │
  │ Sends API request with bearer access token
  ▼
Resource API
  │
  ├── Validates issuer, signature, expiry and audience
  ├── Evaluates scopes and claims
  └── Returns or denies the requested data
```

# Complete responsibilities matrix

| Concern                                                   | Primary responsibility               | Supporting actor                              |
| --------------------------------------------------------- | ------------------------------------ | --------------------------------------------- |
| Store local user accounts                                 | ASP.NET Core Identity                | Soteria database                              |
| Verify user credentials                                   | ASP.NET Core Identity                | Soteria                                       |
| Handle confirmation, recovery, lockout and 2FA            | ASP.NET Core Identity                | Soteria UI                                    |
| Maintain Soteria login session                            | ASP.NET Core Identity                | Browser                                       |
| Initiate OpenID Connect sign-in                           | Consuming web application            | Browser                                       |
| Carry interactive redirects                               | Browser                              | Consuming application and Soteria             |
| Validate client identifier                                | OpenIddict                           | Soteria client registration                   |
| Validate redirect URI                                     | OpenIddict                           | Soteria client registration                   |
| Validate requested grant and response types               | OpenIddict                           | Soteria configuration                         |
| Validate PKCE                                             | OpenIddict                           | Consuming application                         |
| Decide whether the client may request a scope             | Soteria                              | OpenIddict registration permissions           |
| Decide whether consent is required                        | Soteria                              | OpenIddict authorization records              |
| Display consent UI                                        | Soteria                              | Browser                                       |
| Decide whether the user may access a client               | Soteria                              | Future access-management data                 |
| Define available identity claims                          | Soteria                              | ASP.NET Core Identity                         |
| Decide which claims are issued                            | Soteria                              | OpenIddict                                    |
| Decide claim destinations                                 | Soteria                              | OpenIddict                                    |
| Define resource/API audiences                             | Soteria                              | OpenIddict                                    |
| Issue authorization codes                                 | OpenIddict                           | Soteria                                       |
| Issue ID tokens                                           | OpenIddict                           | Soteria-supplied principal                    |
| Issue access tokens                                       | OpenIddict                           | Soteria-supplied scopes, claims and audiences |
| Sign and protect tokens                                   | OpenIddict                           | Soteria credential configuration              |
| Publish discovery metadata                                | OpenIddict                           | Soteria hosting                               |
| Exchange authorization code for tokens                    | Consuming web application            | OpenIddict token endpoint                     |
| Validate the OpenID Connect response                      | Consuming web application middleware | Soteria discovery metadata                    |
| Create the consuming application’s local session          | Consuming web application            | Browser                                       |
| Store/manage the API access token                         | Consuming web application            | Authentication/token infrastructure           |
| Attach bearer token to API requests                       | Consuming web application            | HTTP client infrastructure                    |
| Validate access-token signature                           | Resource API                         | Soteria signing-key metadata                  |
| Validate access-token issuer                              | Resource API                         | Soteria                                       |
| Validate access-token expiry                              | Resource API                         | Token contents                                |
| Validate access-token audience                            | Resource API                         | Soteria-issued token                          |
| Evaluate required API scopes                              | Resource API                         | Soteria-issued token                          |
| Evaluate authorization claims                             | Resource API                         | Soteria-issued token                          |
| Make endpoint-level authorization decision                | Resource API                         | Scopes and claims                             |
| Make client UI/business authorization decisions           | Consuming web application            | Local principal and claims                    |
| Persist users, clients, scopes, authorizations and tokens | Soteria database                     | Identity, OpenIddict and Soteria              |
| Manage future application access assignments              | Soteria                              | Soteria database                              |
| Manage future application-specific roles and claims       | Soteria                              | Soteria database                              |


# Initial Phase 2 Provider Model

Phase 2 will prove both OpenID Connect authentication and OAuth-protected API access.

The initial reference system consists of:

- Soteria as the OpenID Connect Provider and OAuth authorization server.
- A server-side reference web application acting as the OpenID Connect client.
- A distinct reference API acting as the OAuth resource server.

The reference web application authenticates users through Authorization Code Flow with PKCE, creates its own local session, and calls the reference API from server-side code.

Soteria issues:

- An ID token for the reference web application.
- A signed JWT access token whose audience identifies the reference API.
- A refresh token that allows the reference application to renew API access without repeating interactive authentication.

The reference client initially uses implicit consent. This means Soteria does not display a consent page for the trusted client. It does not refer to the deprecated OpenID Connect Implicit Flow.

The initial API authorization model uses:

- One explicit scope for the protected reference endpoint.
- A distinct resource/audience for the reference API.
- Only the claims required to identify and authorise the initial request.

Richer scopes, consent policies, application access rules, roles and application-specific claims are deferred until later phases.

# Trust Boundaries

The initial Phase 2 architecture establishes four distinct trust boundaries.

1. The user trusts Soteria with authentication.
2. The consuming web application trusts Soteria as the OpenID Connect Provider.
3. The resource API trusts Soteria as the issuer of OAuth access tokens.
4. The consuming web application and resource API do not trust one another directly; trust is established through tokens issued by Soteria.

