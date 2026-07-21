This document records significant architectural decisions made during the lifetime of the 
project together with the reasoning behind them. It serves as a historical record to help 
future developers understand why important changes were made and to avoid revisiting previously 
resolved discussions.

2026-07-15

Decision:

Phase 2 will prove both OpenID Connect authentication and OAuth-protected API access.

Soteria will authenticate users through ASP.NET Core Identity and use OpenIddict to issue:

- ID tokens to a server-side reference web application.
- Signed JWT access tokens intended for a distinct reference API resource.
- Refresh tokens so the reference application can renew API access without requiring the user 
- to authenticate again whenever an access token expires.

The reference web application will call the reference API from server-side code. The initial 
reference client will use implicit consent and one explicit API scope. Tokens will initially 
contain only the claims required for the reference workflow.

Reason:

Authenticating the reference web application alone would not prove the complete architecture 
required by Soteria. The intended system must also allow consuming applications to call 
protected APIs using tokens issued by Soteria.

Using a server-side reference client keeps access tokens out of browser storage and reduces the 
initial browser-security and CORS surface.

A distinct API audience ensures that access tokens are issued for and accepted by the intended 
resource server rather than being treated as general-purpose credentials.

Starting with one scope, minimal claims and implicit consent keeps the first implementation 
explicit and narrow while deferring richer permissions, claims and consent policy until client 
application and access management are introduced.

2026-07-16

Decision:

Soteria will use Guid primary keys for ASP.NET Core Identity users and roles.

The change will be made before OpenIddict is integrated with Entity Framework Core so that both 
Identity and OpenIddict use a consistent Guid key model from the beginning.

The existing development database and migration history may be reset rather than supporting an 
in-place string-to-Guid data conversion, provided no existing database or development data must 
be preserved.

Reason:

Using Guid identifiers avoids retaining the ASP.NET Core Identity template's default string key 
type as a long-term persistence decision.

Making the change before OpenIddict persistence is introduced avoids a later migration involving 
both Identity and OpenIddict tables and ensures that the initial OpenIddict schema uses the 
intended key type.

The project is still in early development, and the current database contains no production data. 
Resetting the disposable development schema keeps the migration history clear and avoids 
introducing a complex SQLite table-reconstruction migration solely to preserve temporary 
development data.

2026-07-16

Decision:

Soteria will use OpenIddict-generated development X.509 certificates for its local development 
signing and encryption credentials.

Signing and encryption will use separate certificates. OpenIddict will store and reuse the 
certificates through the certificate store of the development user account running Soteria.

Development credentials will only be registered when the host environment is Development. 
Soteria will not use ephemeral credentials as a fallback outside Development and will not 
reuse the ASP.NET Core HTTPS development certificate for OpenIddict.

Non-development environments will require explicitly configured signing and encryption credentials.

The production credential strategy, including secure storage, provisioning, rotation, renewal 
and hosting-identity access, will be defined when the production hosting model is known. 

IIS-specific certificate access will be reviewed when IIS hosting becomes current work.

Reason:

Persistent development certificates allow authorization codes, tokens and other protected 
protocol artefacts to remain usable across application restarts while avoiding certificate 
files and private-key passwords in the repository.

Separate signing and encryption certificates preserve the distinction between the two security 
purposes and align the development model with the expected production responsibilities.

Restricting the development certificates to the Development environment prevents them from 
becoming an accidental production configuration. Deferring the production implementation 
avoids designing certificate deployment and rotation before the hosting environment and 
operational requirements are known.

2026-07-17

Decision:

OpenIddict bootstrap data will be managed through a dedicated application initialisation service.

The initialisation service will use the OpenIddict manager APIs to create and maintain 
required development bootstrap data, such as scopes and client registrations, in an idempotent 
manner during application startup.

Reason:

OpenIddict entities are intended to be managed through the framework's manager APIs rather 
than Entity Framework data seeding.

Using a dedicated initialisation service keeps application startup configuration focused,
establishes a single pattern for bootstrapping OpenIddict data, and provides a repeatable 
mechanism that can be extended as additional scopes, clients and other bootstrap data are 
introduced.

2026-07-17

Decision:

OpenIddict will validate authorization requests before passing valid requests through to a
Soteria-owned authorization endpoint.

The Soteria authorization endpoint will coordinate interactive authentication using the 
ASP.NET Core Identity application cookie. Unauthenticated users will be redirected to the 
Soteria login workflow with the complete authorization request preserved as the return URL.

After authentication, Soteria will own the application-level authorization workflow and will 
supply the resulting principal and authorization decisions back to OpenIddict for protocol 
response generation.

Reason:

OpenIddict owns OpenID Connect and OAuth protocol validation, while ASP.NET Core Identity owns 
local user authentication and the Soteria session.

Authorization endpoint pass-through preserves this responsibility boundary. Invalid protocol 
requests are rejected by OpenIddict before application logic runs, while valid requests can 
participate in Soteria's authentication, consent, scope, claims and access-policy workflows.

Preserving the complete authorization request allows authentication to occur without losing 
the validated client request or requiring the consuming application to restart the flow.

2026-07-17

Decision:

The initial OpenIddict authorisation workflow will issue a deliberately minimal claims principal.

Following successful ASP.NET Core Identity authentication, Soteria will create a new OpenIddict 
claims principal containing only the mandatory subject (`sub`) claim derived from the 
authenticated Identity user. The principal will be assigned the validated requested scopes 
together with the resources associated with those scopes before being returned to OpenIddict 
for protocol response generation.

Clients configured for implicit consent will be authorised automatically. Clients requiring 
any other consent model will be rejected with the standard `consent_required` OpenID Connect 
error until interactive consent is implemented.

Reason:

Separating the authorisation workflow from claim design establishes the complete protocol 
pipeline while keeping the implementation narrowly focused.

Issuing only the mandatory subject claim avoids prematurely defining token contents before 
the project's identity claim model has been agreed.

Using registered scopes and their associated resources keeps the workflow data-driven and 
avoids duplicating client or resource configuration within the authorisation endpoint.

Rejecting non-implicit consent requests preserves correct OpenID Connect behaviour while 
explicitly deferring the consent user interface to a later milestone.

2026-07-17

Decision:

The initial token model will expose only a minimal set of identity claims.

Both ID tokens and access tokens will initially contain:

- `sub`
- `name`
- `email`

The `sub` claim will always be issued. The `name` claim will only be issued when the `profile` 
scope is granted, and the `email` claim will only be issued when the `email` scope is granted. 
The access token audience will be derived from the resources associated with the granted scopes 
rather than being hard-coded.

Roles, application-specific claims and additional profile claims are deferred until the 
corresponding identity and authorisation features are implemented.

Reason:

A minimal claim model is sufficient for the reference implementation while avoiding premature 
design decisions around application authorisation.

Using scope-based claim destinations aligns claim disclosure with the OpenID Connect scope model 
and ensures only authorised identity information is included in issued tokens.

Deriving audiences from registered scope resources keeps the authorisation workflow data-driven 
and avoids duplicating configuration within the endpoint implementation.

2026-07-17

Decision:

Refresh tokens are issued only when the client requests the standard OpenID Connect `offline_access` 
scope.

Reason:

Requiring offline_access makes long-lived access an explicit client request and avoids issuing 
refresh tokens unnecessarily.

2026-07-18

Decision:

Soteria uses rolling refresh tokens. A successful refresh-token exchange issues a renewed access 
token and a replacement refresh token. Refresh-token reuse is not enabled.

Access-token and refresh-token lifetimes are configured provider-wide through application 
configuration.

The initial lifetimes are:

access token: 15 minutes;
refresh token: 14 days.

Access-token lifetime is represented in configuration as minutes. Refresh-token lifetime is 
represented as days.

The current provider task configures the server-side refresh-token exchange. Token storage, 
expiry detection and automatic renewal within the reference web application remain part of that 
application's OpenID Connect integration.

Reason:

Rolling refresh tokens reduce continued reliance on the same long-lived credential. Requiring the 
client to store the replacement token also establishes the behaviour needed by the later 
reference-client implementation.

Short-lived access tokens reduce the useful lifetime of a compromised bearer credential. A longer 
refresh-token lifetime allows the server-side reference application to renew API access without 
repeatedly requiring interactive authentication.

Provider-wide configuration keeps the initial implementation explicit and consistent. Per-client 
token lifetimes are deferred until a concrete client-management requirement justifies them.

Keeping client renewal orchestration outside this task preserves the delivery-plan boundary and 
avoids pulling forward the reference application's OpenID Connect integration.

2026-07-18

Decision:

Resource APIs validate Soteria-issued access tokens using the OpenIddict validation stack.

During development, Soteria and trusted Resource APIs share a symmetric access-token encryption 
key loaded from an uncommitted .env file. Signing keys continue to be obtained through OpenID 
Connect discovery.

Reason:

OpenIddict encrypts access tokens by default. Using the validation stack preserves OpenIddict's 
intended validation model while avoiding custom token-processing code. The shared development 
encryption key allows independently hosted Resource APIs to decrypt and validate issued access 
tokens while keeping signing credentials private to Soteria.

2026-07-18

Decision:

Automatic access-token renewal is performed by the consuming application's authentication 
infrastructure rather than individual pages or feature components.

API consumers obtain a valid access token from a dedicated token-management service. The service 
is responsible for expiry detection, refresh-token exchange, authentication-ticket updates and 
refresh failure handling.

Reason:

Token lifecycle management is part of the application's authentication infrastructure rather than 
feature behaviour. Centralising it avoids duplicated authentication logic and allows future API 
clients to share the same implementation while keeping feature code focused on business behaviour.

2026-07-19

Decsision:
The Soteria logout endpoint performs sign-out by directly invoking HttpContext.SignOutAsync() 
for both the ASP.NET Core Identity application scheme and the OpenIddict server scheme.

Reason:

This approach was adopted after verification demonstrated reliable RP-initiated logout behaviour. 
Returning a SignOutHttpResult produced inconsistent behaviour during endpoint execution, whereas 
direct sign-out completed reliably.

2026-07-21

Decision:

The initial Soteria client model exposes a single client host rather than directly managing OpenIddict's redirect URI collections.

Administrators enter a single client host when creating or editing a client application.

Soteria derives the client's OpenID Connect endpoints from that host using the standard ASP.NET Core OpenID Connect conventions:

- Redirect URI:
  `/signin-oidc`
- Post-logout redirect URI:
  `/signout-callback-oidc`

The calculated URIs are stored in the OpenIddict client registration and displayed within the administration UI for reference, but are not edited directly.

OpenIddict continues to support multiple redirect URIs and post-logout redirect URIs internally; Soteria deliberately exposes a simpler administration model until a future requirement justifies collection management.

Reason:

The initial project targets privately hosted applications following a consistent hosting convention.

Using a single client host keeps client registration simple while still producing fully functional OpenID Connect registrations.

Deriving the redirect URIs avoids duplicated information, prevents inconsistent endpoint configuration, and reduces administrator error.

The simplified model can be expanded later without preventing Soteria from taking advantage of OpenIddict's underlying support for multiple redirect URIs.

