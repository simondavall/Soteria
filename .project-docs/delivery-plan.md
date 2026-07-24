# Delivery Plan

This document expands the roadmap into implementation milestones and tasks.

Unlike the roadmap, which describes the long-term delivery of the project, this document 
records the expected sequence of implementation work.

The roadmap should remain relatively stable.

The delivery plan is expected to evolve as implementation progresses and architectural 
understanding improves.

Tasks listed here are intentionally concise. Detailed scope, goals and implementation 
notes belong in the Jira task for the relevant RefId.

---

# Phase 2 – OpenID Connect Provider Foundation

## ✓ Milestone 2.1 – Provider Architecture

- ✓ Review and restructure the project roadmap and delivery planning model.
- ✓ Define the OpenID Connect provider architecture.
- ✓ Define the authentication flow between Soteria and consuming applications.
- ✓ Define the initial client application model.
- ✓ Define the boundary between hard-coded configuration and future configuration.

---

## ✓ Milestone 2.2 – Reference Applications

(Initially set up with local independent authentication, which will be replaced with OpenID 
Connect in Milestone 2.3.)

- ✓ Define and create the reference web application with local ASP.NET Core Identity.
- ✓ Define and create the reference resource API.
- ✓ Configure and verify communication between the reference web application and the 
reference resource API.

---

## Milestone 2.3 – OpenIddict Implementation

- ✓ Add the OpenIddict packages.
  - ✓ Add the ASP.NET Core integration package.
  - ✓ Add the Entity Framework Core integration package.
  - ✓ Verify the application builds and existing Identity behaviour remains unchanged.

- ✓ Use Guid keys for ASP.NET Core Identity.
  - ✓ Change ApplicationUser to use a Guid key.
  - ✓ Configure Identity roles to use Guid keys.
  - ✓ Update SoteriaDbContext and Identity registration.
  - ✓ Update code that assumes string Identity identifiers.
  - ✓ Recreate the development database using soteria.db.
  - ✓ Create or replace the Entity Framework migration.
  - ✓ Apply the migration.
  - ✓ Verify existing Identity workflows and the database schema.

- ✓ Integrate OpenIddict with Entity Framework Core.
  - ✓ Configure the OpenIddict Entity Framework stores.
  - ✓ Extend SoteriaDbContext for OpenIddict using Guid OpenIddict entities.
  - ✓ Create the Entity Framework migration.
  - ✓ Apply the migration.
  - ✓ Verify the OpenIddict database schema.

- ✓ Define the development signing and encryption certificate strategy.
  - ✓ Determine how development certificates are generated, stored or loaded.
  - ✓ Define separate signing and encryption credential requirements.
  - ✓ Define certificate persistence and reuse between application restarts.
  - ✓ Define safeguards against using development credentials outside development.
  - ✓ Record the agreed strategy.

- ✓ Register the OpenIddict server and establish the initial provider configuration.
  - ✓ Register the OpenIddict server services.
  - ✓ Register the ASP.NET Core host integration.
  - ✓ Configure development signing credential.
  - ✓ Configure development encryption credential.
  - ✓ Verify the server configuration and credentials load successfully.

- ✓ Configure the OpenID Connect endpoint pipeline.
  - ✓ Verify the authorization endpoint has basic default configuration.
  - ✓ Verify the token endpoint has basic default configuration.
  - ✓ Verify the discovery endpoint and signing-key metadata.
  - ✓ Configure only endpoints supported by the current runnable provider implementation.
  - ✓ Verify the published endpoint metadata.

- ✓ Complete the supported protocol configuration.
  - ✓ Configure Authorization Code Flow.
  - ✓ Configure PKCE requirements.
  - ✓ Disable unsupported flows.
  - ✓ Verify the advertised server capabilities.

- ✓ Register the initial API scope.
  - ✓ Define the scope name.
  - ✓ Associate the scope with the Reference API resource.
  - ✓ Register the scope.

- ✓ Register the reference web application as an OpenID Connect client.
  - ✓ Define the client identifier.
  - ✓ Define the display name.
  - ✓ Configure the client type.
  - ✓ Configure redirect URIs.
  - ✓ Configure authorization and token endpoint permissions.
  - ✓ Configure grant-type permissions.
  - ✓ Configure response-type permissions.
  - ✓ Configure supported scopes.
  - ✓ Configure the consent type.
  - ✓ Configure PKCE requirements.
  - ✓ Verify the client registration.

- ✓ Verify the OpenIddict provider configuration.
  - ✓ Verify discovery metadata.
  - ✓ Verify endpoint availability.
  - ✓ Verify client registration.
  - ✓ Verify scope registration.
  - ✓ Verify unsupported requests are rejected.

---

## Milestone 2.4 – Authentication Workflow

- ✓ Connect OpenIddict to ASP.NET Core Identity.
  - ✓ Configure ASP.NET Core Identity as the authentication mechanism.
  - ✓ Configure the Identity application cookie.
  - ✓ Enable OpenIddict authorization endpoint pass-through to Soteria.
  - ✓ Challenge unauthenticated users through the Soteria login workflow.
  - ✓ Preserve the complete authorization request during authentication.
  - ✓ Verify authenticated users reach the Soteria authorization endpoint via the OpenIddict 
  authorization pipeline.

- ✓ Implement the authorisation workflow.
  - ✓ Handle the authorization request.
  - ✓ Determine whether the user must authenticate.
  - ✓ Determine whether consent is required.
  - ✓ Create the OpenIddict claims principal.
  - ✓ Grant the validated requested scopes.
  - ✓ Resolve resources from granted scopes.
  - ✓ Return the authorised principal to OpenIddict.
  - ✓ Verify successful Authorization Code issuance.

- ✓ Define the initial identity claims.
  - ✓ Define the initial ID token claims.
  - ✓ Define the initial access token claims.
  - ✓ Define claim destinations.
  - ✓ Define the Reference API audience.

- ✓ Configure token issuance.
  - ✓ Issue identity claims.
  - ✓ Issue access tokens.
  - ✓ Issue refresh tokens.
  - ✓ Verify the issued tokens.

- ✓ Configure refresh-token lifecycle.
  - ✓ Define the refresh-token strategy.
  - ✓ Configure refresh-token lifetime.
  - ✓ Configure access-token renewal.
  - ✓ Verify rolling refresh-token rotation.
  - ✓ Verify consent-required behaviour remains unchanged.

- ✓ Configure consent behaviour.
  - ✓ Define consent behaviour for managed client applications.
  - ✓ Configure the agreed consent behaviour.

- ✓ Replace the reference web application's local authentication with OpenID Connect.
  - ✓ Configure OpenID Connect authentication.
  - ✓ Remove local ASP.NET Core Identity authentication.
  - ✓ Preserve the application-local authentication session.

- ✓ Implement automatic access-token renewal using refresh tokens.
  - ✓ Detect expired access tokens.
  - ✓ Renew access tokens using the refresh token.
  - ✓ Persist replacement refresh tokens.
  - ✓ Retry failed API requests after successful renewal.

- ✓ Support logout.
  - ✓ Configure the OpenIddict end-session endpoint.
  - ✓ Configure end-session endpoint pass-through or an equivalent OpenIddict request handler.
  - ✓ Configure the reference client's post-logout redirect URI.
  - ✓ Configure any required end-session endpoint permission.
  - ✓ Configure RP-initiated logout.
  - ✓ Sign the user out of Soteria.
  - ✓ Sign the user out of the reference application.
  - ✓ Verify post-logout redirect behaviour.

---

## Milestone 2.5 – End-to-End Verification

- ✓ Verify successful authentication.
  - ✓ Authenticate the reference web application.
  - ✓ Verify successful sign-in.
  - ✓ Verify authenticated application access.

- ✓ Verify unsuccessful authentication scenarios.
  - ✓ Verify anonymous access.
  - ✓ Verify invalid credentials.
  - ✓ Verify unauthorised client requests.
  - ✓ Verify invalid redirect URIs.

- ✓ Verify protected API access.
  - ✓ Call the Reference API using an access token.
  - ✓ Verify successful API authorisation.
  - ✓ Verify rejected requests without an access token.
  - ✓ Verify rejected requests with an invalid access token.

- ✓ Verify access-token renewal.
  - ✓ Verify refresh-token use.
  - ✓ Verify renewed access tokens.
  - ✓ Verify expired access-token handling.

- ✓ Verify logout.
  - ✓ Verify reference application logout.
  - ✓ Verify Soteria logout.
  - ✓ Verify access after logout is denied.

---

# Phase 3 – Client Application Management

## Milestone 3.1 – Client Administration

- ✓ Create the client application management feature.
  - ✓ Define authenticated administration navigation.
  - ✓ Create the authenticated client application list page layout.
  - ✓ Create the authenticated client details page layout.
  - ✓ Define the client management navigation workflow.

- ✓ Implement client application listing.
  - ✓ Retrieve registered OpenIddict applications.
  - ✓ Display application summary information.
  - ✓ Display client type and consent type.
  - ✓ Display application status (currently Active for all applications; enabled/disabled state will be introduced in Milestone 3.2).
  - ✓ Verify application listing.

- ✓ Implement client application details.
  - ✓ Retrieve the selected OpenIddict application.
  - ✓ Display client type and consent configuration.
  - ✓ Display configured endpoint permissions.
  - ✓ Display configured grant type permissions.
  - ✓ Display configured response type permissions.
  - ✓ Display configured scopes.
  - ✓ Display configured redirect URIs.
  - ✓ Display configured post-logout redirect URIs.
  - ✓ Verify application details.

---

## Milestone 3.2 – Client Management

- ✓ Create client applications.
  - ✓ Define the client creation workflow.
  - ✓ Create OpenIddict applications.
  - ✓ Validate required client information.
  - ✓ Verify application creation.

- ✓ Edit client applications.
  - ✓ Define the client edit workflow.
  - ✓ Update the display name.
  - ✓ Replace the client secret.
  - ✓ Update the client host.
  - ✓ Recalculate the redirect URI and post-logout redirect URI from the updated client host.
  - ✓ Preserve the immutable client identifier.
  - ✓ Verify application updates.

- ✓ Enable and disable client applications.
  - ✓ Define the enabled state.
  - ✓ Persist the enabled state on the client application.
  - ✓ Prevent disabled applications from starting new authentication.
  - ✓ Prevent disabled applications from obtaining new tokens.
  - ✓ Allow existing access tokens to remain valid until expiry.
  - ✓ Display application status.
  - ✓ Verify enabled and disabled behaviour.

- ✓ Implement user-friendly OpenID Connect authentication error handling.
  - ✓ Define the provider-owned OpenID Connect error-handling process.
  - ✓ Present browser-facing authorization errors through a shared Soteria error page.
  - ✓ Map recognised OpenID Connect protocol errors to user-friendly messages.
  - ✓ Display safe fallback content for unrecognised errors.
  - ✓ Keep protocol validation within OpenIddict and presentation within Soteria.
  - ✓ Verify disabled-client authentication displays the friendly error page.

---

# Phase 4 – Identity Management

## Milestone 4.1 – User Administration

- ✓ Create the user administration feature.
  - ✓ Define authenticated administration navigation.
  - ✓ Create the authenticated user list page layout.
  - ✓ Create the authenticated user details page layout.
  - ✓ Define the user administration navigation workflow.

- ✓ Implement user listing.
  - ✓ Retrieve registered users.
  - ✓ Display user summary information.
  - ✓ Display account status.
  - ✓ Support searching users.
  - ✓ Verify user listing.

- Implement user details.
  - Retrieve the selected user.
  - Display account information.
  - Display profile information.
  - Display email information.
  - Display lockout information.
  - Verify user details.

- Create user accounts.
  - Define the administrative registration workflow.
  - Create new user accounts.
  - Support registration of existing users.
  - Associate users with one or more client applications.
  - Send the account confirmation email.
  - Verify user registration.

- Edit user accounts.
  - Define the user edit workflow.
  - Update account information.
  - Update profile information.
  - Update client application assignments.
  - Verify user account updates.

---

## Milestone 4.2 – Identity Account Management

- Manage passwords.
  - Reset user passwords.
  - Generate temporary passwords.
  - Verify password reset behaviour.

- Manage email addresses.
  - Update email addresses.
  - Manage email confirmation.
  - Resend confirmation emails.
  - Verify email management.

- Manage account lockout.
  - Display lockout status.
  - Remove account lockout.
  - Verify lockout management.

- Manage user profile information.
  - Update display name.
  - Update profile information.
  - Verify profile updates.

---

## Milestone 4.3 – User Self-Service

- Review the existing ASP.NET Core Identity pages.
  - Identify reusable functionality.
  - Identify required customisation.
  - Define the self-service workflow.

- Integrate user self-service.
  - Configure account management.
  - Configure profile management.
  - Configure password management.
  - Verify self-service account management.

- Integrate two-factor authentication.
  - Configure authenticator application support.
  - Configure recovery codes.
  - Configure two-factor management.
  - Verify two-factor authentication.

- Verify the self-service experience.
  - Verify profile management.
  - Verify password management.
  - Verify email confirmation.
  - Verify two-factor authentication.

  
---

# Phase 5 – Application Access Management

## Milestone 5.1 – Client User Management

- Assign users to client applications.
- Remove users from client applications.
- Manage client application membership.

## Milestone 5.2 – Client Administration

- Appoint Client Administrators.
- Revoke Client Administrator privileges.
- Manage client administrator assignments.

## Milestone 5.3 – Application Roles

- Define application roles.
- Assign application roles.
- Revoke application roles.

## Milestone 5.4 – Claims & Authorisation

- Define application claims.
- Configure claim issuance.
- Restrict administration pages.
- Enforce application authorisation.

## Milestone 5.5 – OpenID Connect Integration

- Enforce client assignment during authorisation.
- Enforce client assignment during token redemption.
- Enforce client assignment during refresh token redemption.

---

# Phase 6 – External Identity Providers

## Milestone 6.1 – Federation

- Configure external identity providers.
- External login management.
- Account linking.

## Milestone 6.2 – Identity Synchronisation

- External identity synchronisation.
- Claims mapping.
- Federation enhancements.

---

# Phase 7 – Operational Features

## Milestone 7.1 – Auditing

- Audit user administration.
- Audit application administration.
- Audit authentication activity.

## Milestone 7.2 – Monitoring

- Operational monitoring.
- Health reporting.
- Administrative diagnostics.

## Milestone 7.3 – Production Readiness

- Security review.
- Performance review.
- Deployment preparation.
- Production validation.

---

# Phase 8 - Extended Application Configuration

## Milestone 8.1 – OpenID Connect Configuration

- Manage client type.
  - Configure the client as public or confidential.
  - Apply the authentication requirements appropriate to the selected client type.
  - Verify public and confidential client authentication.

- Manage OpenID Connect permissions.
  - Configure endpoint permissions.
  - Configure grant type permissions.
  - Configure response type permissions.
  - Configure scope permissions.
  - Configure PKCE requirements.
  - Configure consent behaviour.
  - Verify permission changes.

---

