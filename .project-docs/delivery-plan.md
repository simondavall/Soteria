# Delivery Plan

This document expands the roadmap into implementation milestones and tasks.

Unlike the roadmap, which describes the long-term delivery of the project, this document records the expected sequence of implementation work.

The roadmap should remain relatively stable.

The delivery plan is expected to evolve as implementation progresses and architectural understanding improves.

Tasks listed here are intentionally concise. Detailed scope, goals and implementation notes belong in the Jira task for the relevant RefId.

---

# Phase 2 – OpenID Connect Provider Foundation

## Milestone 2.1 – Provider Architecture

- ✓ Review and restructure the project roadmap and delivery planning model.
- ✓ Define the OpenID Connect provider architecture.
- ✓ Define the authentication flow between Soteria and consuming applications.
- ✓ Define the initial client application model.
- ✓ Define the boundary between hard-coded configuration and future configuration.

---

## Milestone 2.2 – Reference Applications
(Initially set up with local independant auth, which will be replaced with OpenID Connect in Milestone 2.3)
- Define and create the reference web application with local ASP.NET Core Identity.
- Define and create the reference resource API.
- Configure and verify communication between the reference web application and the reference resource API.

---

## Milestone 2.3 – OpenIddict Implementation

- Add and configure OpenIddict.
- Integrate OpenIddict with Entity Framework Core.
- Configure OpenID Connect endpoints.
- Configure Authorization Code Flow with PKCE.
- Define development signing and encryption certificate strategy.
- Configure development signing and encryption credentials.
- Replace the reference web application's local authentication with OpenID Connect.
- Verify OpenID Connect authentication.

---

## Milestone 2.4 – Development Client Registration

- Define the initial scopes and claims.
- Register the reference client application.
- Configure redirect URIs.
- Configure permissions and grant types.
- Configure supported scopes.

---

## Milestone 2.5 – Authentication Workflow

- Connect OpenIddict to ASP.NET Core Identity.
- Implement the authorisation workflow.
- Define access-token renewal and refresh-token lifecycle.
- Implement access-token renewal and refresh-token lifecycle.
- Define consent behaviour for managed client applications.
- Implement the agreed consent behaviour.
- Issue identity claims.
- Issue access tokens.
- Issue refresh tokens.
- Support logout.

---

## Milestone 2.6 – End-to-End Verification

- Authenticate the reference web application.
- Verify successful authentication.
- Verify unsuccessful authentication scenarios.
- Verify protected API access.
- Verify access-token renewal.
- Verify logout.
- Record permanent regression verification.

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
