This document provides a snapshot of the current implementation state of the project. 
It records completed work, the feature currently being developed, and the next expected 
steps. It should be updated regularly and is intended to help developers quickly understand 
where development should continue.

# Current phase

## Phase 5 – Application Authorisation

# Current milestone

## Milestone 5.5 – System Administration Bootstrap

# Current task

- Verify System Role isolation.
  - Verify System Roles do not create Client Memberships.
  - Verify System Roles do not grant consuming-application access.
  - Verify System Roles are not included in ID tokens.
  - Verify System Roles are not included in access tokens.
  - Verify Application Role claim issuance remains unchanged.
  - Verify removing a System Role does not alter Client Memberships.
  - Verify removing a Client Membership does not alter System Role assignments.

# Remaining milestone tasks

-None

# Completed capabilities

## Project foundations

- Established the overall project structure, documentation set and delivery planning process.
- Established the shared MudBlazor application layout, theme and navigation patterns.
- Established the project's Entity Framework, dialog, lookup, validation and application-service implementation patterns.

## Identity and authentication

- Integrated ASP.NET Core Identity using Guid identifiers.
- Implemented authenticated administration using the Identity application cookie.
- Preserved standard Identity workflows including email confirmation, lockout and account management.
- Added administrative user registration and account management.

## OpenID Connect provider

- Implemented Soteria as an OpenID Connect Provider and OAuth authorisation server using OpenIddict.
- Configured Authorization Code Flow with mandatory PKCE.
- Implemented authorisation, token issuance, refresh-token rotation and RP-initiated logout.
- Configured OpenID Connect discovery, signing credentials, encryption credentials and development bootstrap.
- Implemented user-friendly browser-facing authentication error handling.

## Reference applications

- Implemented the Reference Web application using OpenID Connect authentication.
- Implemented the Reference Resource API using access-token validation.
- Verified complete end-to-end authentication, API authorisation and automatic token renewal.

## Client application management

- Implemented authenticated client administration.
- Added client application creation, editing, enable/disable and validation.
- Simplified client registration through host-based endpoint generation.
- Added Application Role management with creation, editing, deletion and validation.

## User administration

- Implemented authenticated user administration.
- Added user listing, searching and detailed account information.
- Added administrative user creation.
- Added account unlock support.
- Added user profile support including Display Name.

## Application authorisation model

- Implemented the complete application authorisation persistence model.
- Added System Roles, Client Memberships, Membership Levels, Application Roles and Application Role assignments.
- Enforced ownership, uniqueness and client isolation throughout the persistence model.
- Configured appropriate entity relationships and deletion behaviour.

## Client membership management

- Added Client Membership management from User Details.
- Implemented Client Membership creation, editing and removal.
- Added Membership Level management.
- Added Application Role assignment management.
- Prevented duplicate memberships and invalid cross-client role assignments.

## Claims and consuming application authorisation

- Implemented client-isolated Application Role claim issuance.
- Issued Application Role claims to ID and access tokens.
- Configured policy-based authorisation in both the Reference Web application and Reference API.
- Verified end-to-end consuming application authorisation.

## System administration

- Implemented idempotent bootstrap of the initial Soteria Administrator.
- Added Soteria Administrator management through User Administration.
- Prevented removal of the final Soteria Administrator.
- Implemented persisted System Role authorisation using ASP.NET Core authorisation policies.
- Introduced the reusable current-user authorisation abstraction.
- Enforced privileged operations through both UI visibility and application-service authorisation.
- Preserved complete isolation between System Roles and client-facing Application Roles.

