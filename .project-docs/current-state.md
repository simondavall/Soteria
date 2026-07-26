This document provides a snapshot of the current implementation state of the project. 
It records completed work, the feature currently being developed, and the next expected 
steps. It should be updated regularly and is intended to help developers quickly understand 
where development should continue.

# Current phase

## Phase 5 – Application Authorisation

# Current milestone

## Milestone 5.1 – Authorisation Persistence Model

# Current task

- Create the Authorization persistence model.

# Remaining milestone tasks

- None

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
- Defined implicit consent as the only supported behaviour for managed client applications.
- Configured and verified implicit consent behaviour.
- Replaced the Reference Web application's local ASP.NET Core Identity authentication with OpenID Connect.
- Configured the Reference Web application as a confidential OpenID Connect client.
- Added local `.env` configuration for development secrets.
- Configured the Reference API to validate access tokens issued by Soteria.
- Verified end-to-end authentication and protected API access.
- Implemented automatic access-token renewal in the Reference Web application.
- Added proactive access-token expiry detection.
- Added refresh-token exchange through Soteria's token endpoint.
- Persisted replacement access tokens and rolling refresh tokens in the local authentication session.
- Added a single protected API retry following forced token renewal.
- Verified renewal failure invalidates the local consuming-application session.
- Verified tokens remain unavailable to browser application code.
- Verified automatic renewal end to end.
- Implemented RP-initiated OpenID Connect logout.
- Added the OpenIddict end-session endpoint.
- Implemented Soteria end-session handling.
- Configured Reference Web application logout.
- Registered post-logout redirect URIs.
- Verified complete logout workflow and authentication regression.
- Added authenticated administration navigation.
- Created the initial client application list and details pages.
- Enabled the MudBlazor dark theme.
- Implemented the authenticated client application listing page.
- Displayed application summary information.
- Displayed the initial application status column.
- Implemented the client application details page.
- Retrieved OpenIddict application configuration directly from the database.
- Defined the client creation workflow.
- Implemented client application creation.
- Added a shared OpenIddict application defaults helper.
- Implemented FluentValidation-based client validation.
- Introduced a dedicated client application lookup service.
- Verified successful client application creation.
- Defined the client edit workflow.
- Implemented client application editing.
- Implemented optional client secret replacement.
- Implemented client host updates.
- Derived redirect URI and post-logout redirect URI from the client host.
- Verified successful client application updates.
- Implemented explicit client application enabled state.
- Added custom SoteriaApplication OpenIddict entity.
- Persisted client enabled state.
- Updated client administration UI to manage enabled state.
- Prevented disabled client applications from starting new OpenID Connect authentication.
- Prevented disabled client applications from redeeming authorization codes.
- Prevented disabled client applications from redeeming refresh tokens.
- Verified existing access tokens remain valid until expiry.
- Verified re-enabling a client immediately restores authentication.
- Added a shared authentication error page for browser-facing OpenID Connect failures.
- Integrated OpenIddict status-code pages with ASP.NET Core.
- Mapped recognised protocol errors to user-friendly messages.
- Added safe fallback handling for unrecognised authentication errors.
- Preserved OpenIddict protocol validation while separating presentation into Soteria.
- Excluded the error page from interactive routing to preserve the OpenIddict server response during status-code re-execution.
- Added authenticated user administration navigation.
- Created the initial user list page.
- Created the initial user details page.
- Established the user administration navigation workflow.
- Implemented the user administration listing.
- Added the user feature service using the established direct Entity Framework Core query pattern.
- Displayed user email, email-confirmation status and current lockout status.
- Added client-side user searching.
- Preserved user-row navigation to the user details page.
- Added the DisplayName profile property to ApplicationUser.
- Recreated the Identity Entity Framework migration from the current model.
- Recreated the development database.
- Updated ASP.NET Core Identity profile management to allow users to maintain their display name.
- Preserved nullable DisplayName semantics, allowing the application to fall back to the username where required.
- Updated the user administration listing to display Username and DisplayName separately.
- Implemented the user details page.
- Added a dedicated user details query using the established direct Entity Framework Core pattern.
- Displayed account, profile, email and lockout information for the selected user.
- Added graceful handling for unknown users.
- Preserved read-only administration workflow pending user editing.
- Refined the user details page into consolidated User Details and Permissions sections.
- Added Create User dialog from the User Administration page.
- Implemented administrative registration for new Identity users.
- Existing users now redirect directly to their User Details page.
- UserName and Email are both initialised from the submitted email address.
- Reused the existing ASP.NET Core Identity confirmation email workflow.
- Added FluentValidation for both client-side and server-side validation.
- Permissions remain a Phase 5 placeholder.
- Added Edit User dialog launched from the User Details page.
- Displayed all user account information as read-only.
- Implemented administrative account unlock workflow.
- Unlock updates the dialog immediately and persists only when Save is selected.
- Cleared LockoutEnd when unlocking an account.
