This document provides a snapshot of the current implementation state of the project. It records completed work, the feature currently being developed, and the next expected steps. It should be updated regularly and is intended to help developers quickly understand where development should continue.

# Current phase

Phase 2 – OpenID Connect Provider Foundation

# Completed

- Established the initial project structure.
- Created the project documentation.
- Defined the project vision and roadmap.
- Added and configured MudBlazor 9.6.
- Established the initial application theme.
- Configured the MudBlazor providers.
- Established the shared application layout.
- Migrated the built-in ASP.NET Core Identity UI to the project UI conventions.
- Added development email sender for Identity.
- Preserved ASP.NET Core Identity behaviour and static SSR workflows.
- Established the project Identity implementation patterns.
- Reviewed and restructured the project roadmap and delivery planning model.
- Defined the OpenID Connect provider architecture.
- Defined the authentication flow between Soteria and consuming applications.
- Defined the initial client application model.
- Defined the boundary between hard-coded configuration and future configuration.
- Defined and created the reference web application.
- Defined and created the reference Resource API.
- Verified communication between the reference web application and the reference Resource API.
- Added the required OpenIddict packages.
- Changed ASP.NET Core Identity users and roles to use Guid keys.
- Recreated the development database as soteria.db.
- Renamed the Soteria database connection to SoteriaDb.
- Recreated and applied the initial Identity migration.
- Verified the Guid-based Identity schema and existing Identity workflows.
- Configured the OpenIddict Entity Framework Core stores.
- Extended SoteriaDbContext to include the OpenIddict entity model.
- Created and applied the initial OpenIddict Entity Framework migration.
- Verified the OpenIddict database schema.
- Defined the development signing and encryption certificate strategy.
- Confirmed that local Rider execution runs Soteria under the interactive development account.
- Defined separate OpenIddict development signing and encryption certificates.
- Defined Development-only credential registration and deferred the production and IIS credential strategy.
- Registered the OpenIddict server services and ASP.NET Core host integration.
- Configured the initial OpenIddict Authorization and Token endpoint URIs.
- Enabled Authorization Code Flow as the initial supported protocol flow.
- Generated and verified the OpenIddict development signing and encryption certificates.
- Verified that the development certificates are reused between application restarts.
- Verified the authorization and token endpoints hav basic default configuration.
- Verified the discovery endpoint and signing-key metadata.
- Verified the published endpoint metadata.
- Confirmed Authorization Code Flow as the only supported protocol flow.
- Mandated PKCE for all Authorization Code clients.
- Verified the advertised grant type, response type and PKCE capabilities.
- Registered the reference web application client with an OpenIddict initializer.
- Verified discovery metadata.
- Verified endpoint availability.
- Verified client registration.
- Verified scope registration.
- Verified unsupported requests are rejected.
- Enabled OpenIddict authorization endpoint pass-through.
- Added the Soteria authorization endpoint.
- Connected OpenIddict authorization requests to the ASP.NET Core Identity authentication workflow.
- Redirected unauthenticated authorization requests to the Soteria login page.
- Preserved the complete OpenID Connect authorization request through login.
- Verified authenticated users return to the Soteria authorization endpoint through the OpenIddict authorization pipeline.
- Added a temporary authenticated response that ends the incomplete authorization workflow without creating a redirect loop.
- Implemented the OpenIddict authorisation workflow.
- Created the initial OpenIddict claims principal.
- Granted validated scopes and resolved associated resources.
- Returned authorised principals to OpenIddict for protocol response generation.
- Verified successful Authorization Code issuance.
- Verified implicit consent behaviour.
- Verified clients requiring consent are rejected with `consent_required`.
- Verified stale Identity sessions are handled safely.
- Defined the initial ID token claims.
- Defined the initial access token claims.
- Implemented scope-based claim destinations.
- Defined the initial Reference API audience.
- Registered the standard OpenID Connect profile and email scopes.
- Verified scope-sensitive claim issuance.
- Configured the OpenIddict token endpoint.
- Enabled ID token issuance.
- Enabled access token issuance.
- Enabled refresh token issuance using the Refresh Token grant.
- Registered the standard `offline_access` scope.
- Configured refresh tokens to be issued only when the `offline_access` scope is requested.
- Verified that refresh tokens are issued when `offline_access` is requested and omitted otherwise.
- Defined the refresh-token strategy.
- Configured refresh-token lifetime.
- Configured access-token renewal.
- Verified rolling refresh-token rotation.
- Verified consent-required behaviour remains unchanged.

# Current milestone

Milestone 2.4 – Authentication Workflow

# Current task

Configure consent behaviour.
- Define consent behaviour for managed client applications.
- Configure the agreed consent behaviour.

# Next

- Replace the reference web application's local authentication with OpenID Connect.