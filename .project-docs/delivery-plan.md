# Delivery Plan

This document expands the roadmap into implementation milestones and tasks.

Unlike the roadmap, which describes the long-term delivery of the project, this document records the expected sequence of implementation work.

The roadmap should remain relatively stable.

The delivery plan is expected to evolve as implementation progresses and architectural understanding improves.

Tasks listed here are intentionally concise. Detailed scope, goals and implementation notes belong in the Jira task for the relevant RefId.

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

(Initially set up with local independent authentication, which will be replaced with OpenID Connect in Milestone 2.3.)

- ✓ Define and create the reference web application with local ASP.NET Core Identity.
- ✓ Define and create the reference resource API.
- ✓ Configure and verify communication between the reference web application and the reference resource API.

---

## Milestone 2.3 – OpenIddict Implementation

- ✓ Add the OpenIddict packages.
  - Add the ASP.NET Core integration package.
  - Add the Entity Framework Core integration package.
  - Verify the application builds and existing Identity behaviour remains unchanged.

- ✓ Use Guid keys for ASP.NET Core Identity.
  - Change ApplicationUser to use a Guid key.
  - Configure Identity roles to use Guid keys.
  - Update SoteriaDbContext and Identity registration.
  - Update code that assumes string Identity identifiers.
  - Recreate the development database using soteria.db.
  - Create or replace the Entity Framework migration.
  - Apply the migration.
  - Verify existing Identity workflows and the database schema.

- ✓ Integrate OpenIddict with Entity Framework Core.
  - Configure the OpenIddict Entity Framework stores.
  - Extend SoteriaDbContext for OpenIddict using Guid OpenIddict entities.
  - Create the Entity Framework migration.
  - Apply the migration.
  - Verify the OpenIddict database schema.

- ✓ Define the development signing and encryption certificate strategy.
  - Determine how development certificates are generated, stored or loaded.
  - Define separate signing and encryption credential requirements.
  - Define certificate persistence and reuse between application restarts.
  - Define safeguards against using development credentials outside development.
  - Record the agreed strategy.

- Register the OpenIddict server and development credentials.
  - Register the OpenIddict server services.
  - Register the ASP.NET Core host integration.
  - Configure development signing credential.
  - Configure development encryption credential.
  - Verify the server configuration and credentials load successfully.

- Configure the OpenID Connect endpoints.
  - Configure the discovery endpoint.
  - Configure the authorization endpoint.
  - Configure the token endpoint.
  - Configure the logout endpoint.
  - Configure the required OpenID Connect endpoints only.

- Configure the supported protocol flow.
  - Configure Authorization Code Flow.
  - Configure PKCE requirements.
  - Disable unsupported flows.
  - Verify the advertised server capabilities.

- Register the initial API scope.
  - Define the scope name.
  - Associate the scope with the Reference API resource.
  - Register the scope.

- Register the reference web application as an OpenID Connect client.
  - Define the client identifier.
  - Define the display name.
  - Configure the client type.
  - Configure the client authentication method.
  - Configure redirect URIs.
  - Configure post-logout redirect URIs.
  - Configure endpoint permissions.
  - Configure grant-type permissions.
  - Configure response-type permissions.
  - Configure supported scopes.
  - Configure the consent type.
  - Configure PKCE requirements if enforced per client.

- Verify the OpenIddict provider configuration.
  - Verify discovery metadata.
  - Verify endpoint availability.
  - Verify client registration.
  - Verify scope registration.
  - Verify unsupported requests are rejected.

---

## Milestone 2.4 – Authentication Workflow

- Connect OpenIddict to ASP.NET Core Identity.
  - Configure ASP.NET Core Identity as the authentication mechanism.
  - Configure the Identity application cookie.
  - Configure OpenIddict to use the authenticated Identity principal.
  - Verify authenticated users reach the OpenIddict pipeline.

- Implement the authorisation workflow.
  - Handle the authorization request.
  - Determine whether the user must authenticate.
  - Determine whether consent is required.
  - Create the OpenIddict claims principal.
  - Return the authorised principal to OpenIddict.

- Define the initial identity claims.
  - Define the initial ID token claims.
  - Define the initial access token claims.
  - Define claim destinations.
  - Define the Reference API audience.

- Configure token issuance.
  - Issue identity claims.
  - Issue access tokens.
  - Issue refresh tokens.
  - Verify the issued tokens.

- Configure refresh-token lifecycle.
  - Define the refresh-token strategy.
  - Configure refresh-token lifetime.
  - Configure access-token renewal.

- Configure consent behaviour.
  - Define consent behaviour for managed client applications.
  - Configure the agreed consent behaviour.

- Replace the reference web application's local authentication with OpenID Connect.
  - Configure OpenID Connect authentication.
  - Remove local ASP.NET Core Identity authentication.
  - Preserve the application-local authentication session.

- Support logout.
  - Configure RP-initiated logout.
  - Sign the user out of Soteria.
  - Sign the user out of the reference application.

- Verify successful OpenID Connect authentication.
  - Authenticate the reference web application.
  - Verify successful sign-in.
  - Verify successful sign-out.

---

## Milestone 2.5 – End-to-End Verification

- Verify successful authentication.
  - Authenticate the reference web application.
  - Verify successful sign-in.
  - Verify authenticated application access.

- Verify unsuccessful authentication scenarios.
  - Verify anonymous access.
  - Verify invalid credentials.
  - Verify unauthorised client requests.
  - Verify invalid redirect URIs.

- Verify protected API access.
  - Call the Reference API using an access token.
  - Verify successful API authorisation.
  - Verify rejected requests without an access token.
  - Verify rejected requests with an invalid access token.

- Verify access-token renewal.
  - Verify refresh-token use.
  - Verify renewed access tokens.
  - Verify expired access-token handling.

- Verify logout.
  - Verify reference application logout.
  - Verify Soteria logout.
  - Verify access after logout is denied.

- Record permanent regression verification.
  - Record the agreed verification checklist.
  - Capture any regression tests discovered during implementation.

---

# Phase 3 – Client Application Management

## Milestone 3.1 – Client Administration

- Create the client application management feature.
- List registered client applications.
- View client details.

---

## Milestone 3.2 – Client Registration

- Create client applications.
- Edit client applications.
- Enable and disable client applications.
- Manage application metadata.

---

## Milestone 3.3 – OpenID Connect Configuration

- Manage redirect URIs.
- Manage post-logout redirect URIs.
- Manage client authentication.
- Manage permissions.
- Replace hard-coded client registration.

---

# Phase 4 – Identity Management

## Milestone 4.1 – User Administration

- Browse users.
- Search users.
- View user details.

---

## Milestone 4.2 – User Management

- Create users.
- Edit users.
- Enable and disable users.
- Manage passwords.
- Manage email addresses.
- Manage lockout.

---

## Milestone 4.3 – Identity Enhancements

- Continue expanding identity management capabilities.

---

# Phase 5 – Application Access Management

## Milestone 5.1 – Application Access

- Grant and revoke application access.
- Browse application assignments.

---

## Milestone 5.2 – Roles

- Manage application roles.
- Assign user roles.

---

## Milestone 5.3 – Claims

- Manage application claims.
- Determine issued claims.
- Issue application authorisation information.
