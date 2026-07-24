# Soteria Authorisation Design Discussion

> **Status:** Working design discussion
>
> This document records the architectural discussion that took place during the planning of Phase 4. It is **not** part of the current implementation.
>
> Its purpose is to capture the agreed direction for Phase 5 so that a future implementation can begin with the existing reasoning rather than repeating the architectural discussion.
>
> Unless superseded by later project decisions, this document should be treated as the starting point for Phase 5 planning.

---

# Background

During planning for Phase 4 it became apparent that the project originally blurred two separate concerns:

* user account management;
* application authorisation.

After discussion it was agreed that these should remain separate responsibilities.

Phase 4 focuses on **Identity Management**.

Phase 5 focuses on **Application Access Management**.

This separation aligns with Soteria's role as both an Identity Provider and an authorisation service.

---

# Overall Responsibility Model

ASP.NET Core Identity remains responsible for:

* user accounts;
* passwords;
* email confirmation;
* lockout;
* two-factor authentication;
* account recovery;
* authentication.

Soteria is responsible for:

* client applications;
* application access;
* application administration;
* application roles;
* application claims;
* authorisation decisions;
* determining which authorisation information is issued to consuming applications.

Identity determines **who the user is**.

Soteria determines **what the user may do**.

---

# User Categories

Three logical categories of user were identified.

## Soteria Administrator

A Soteria Administrator has unrestricted access to Soteria itself.

Responsibilities include:

* managing client applications;
* registering Client Administrators;
* managing all user accounts;
* overriding client administration when necessary.

This is considered a global Soteria responsibility rather than a client-specific responsibility.

---

## Client Administrator

A Client Administrator administers one or more specific client applications.

Responsibilities include:

* registering users;
* assigning users to client applications;
* appointing additional Client Administrators;
* revoking Client Administrator privileges;
* assigning application roles;
* removing application access;
* clearing account lockout.

Client Administrators should not become global administrators.

Their authority exists only within the client applications they administer.

---

## Client User

Client Users authenticate through Soteria and manage their own account.

Responsibilities include:

* changing passwords;
* configuring two-factor authentication;
* managing their own profile;
* maintaining their own account using the existing ASP.NET Core Identity pages.

They do not manage their own application permissions.

---

# Registration Model

The existing ASP.NET Core Identity self-registration model will be replaced.

Users do not register themselves.

Registration becomes an administrative workflow.

Only administrators have access to the Register page.

Initially this page will remain unrestricted during Phase 4 development. Phase 5 introduces the required authorisation.

---

## Creating a new user

A Client Administrator supplies:

* email address;
* temporary password;
* confirmation password;
* one or more client applications.

The list of client applications is restricted to those administered by the current Client Administrator.

At least one client must be selected.

If the email address does not already exist:

* a new Soteria account is created;
* client assignments are created;
* an email confirmation message is sent.

The confirmation email links directly to the Change Password workflow rather than the default email confirmation page.

Successfully changing the password also marks the email address as confirmed.

The temporary password is communicated to the user outside Soteria.

The temporary password is never included in email.

---

## Existing users

Registration also supports existing Soteria users.

If the supplied email address already belongs to an existing account:

* a second Soteria account is not created;
* new client assignments are added;
* existing client assignments remain unchanged.

This allows one Soteria identity to belong to multiple client applications.

---

# Visibility Rules

Client Administrators only see information necessary to administer users belonging to the client applications they administer.

Initially this includes:

* display name;
* email address;
* email confirmed;
* lockout status;
* client assignment status;
* client roles.

Client Administrators do not see assignments belonging to client applications they do not administer.

They do not gain visibility of unrelated client information.

---

# Client Administration

Client Administrators may appoint additional Client Administrators.

They may also revoke Client Administrator privileges.

Every client application must always have at least one Client Administrator.

This constraint should be enforced when changes are saved rather than when a client application is initially created.

This allows Soteria Administrators to create new client applications before assigning the first Client Administrator.

---

# User Enable / Disable

During this discussion the previously proposed global user enabled/disabled state was reconsidered.

The conclusion reached was that a separate enabled flag may not be required.

Instead, application access is controlled through client assignments.

Removing a user's assignment from a client application prevents access to that client while leaving access to other client applications unaffected.

This approach is considered simpler and more closely reflects the project's authorisation model.

This remains subject to review during Phase 5 implementation.

---

# Application Assignments

Users may belong to multiple client applications.

Each client application independently determines:

* whether the user has access;
* whether the user is a Client Administrator;
* which application roles are assigned.

Application assignments therefore become part of Soteria's own domain model rather than ASP.NET Core Identity.

---

# Roles and Claims

The discussion concluded that roles and claims have different responsibilities.

Roles define permissions.

Claims communicate identity and authorisation information to consuming applications.

The current expectation is:

* application roles are stored by Soteria;
* Soteria determines which roles are transformed into issued claims;
* consuming applications make authorisation decisions using those claims.

Exactly how roles are persisted remains a Phase 5 design activity.

---

# Phase Boundaries

## Phase 4

Phase 4 establishes the user management experience.

It intentionally leaves all pages accessible during development.

The objective is to produce the required pages, services and components without introducing the complete authorisation model.

---

## Phase 5

Phase 5 introduces the security model.

This includes:

* page authorisation;
* application assignments;
* Client Administrator restrictions;
* role management;
* claim issuance;
* enforcement during OpenID Connect authorisation;
* enforcement during authorisation-code redemption;
* enforcement during refresh-token redemption.

The components produced during Phase 4 should therefore be designed so these restrictions can be added without significant restructuring.

---

# Open Questions

The following topics remain intentionally undecided.

## Storage model

The persistence model for:

* application assignments;
* application roles;
* role assignment.

---

## Claim issuance

Exactly which application roles become claims.

Exactly which claims are issued to each consuming application.

---

## Enforcement

The implementation details for checking application assignments during:

* OpenID Connect authorisation;
* authorisation-code redemption;
* refresh-token redemption.

---

## Client Administration

Whether additional delegated administration capabilities become necessary once the initial implementation has been proven.

---

# Design Principles

The following principles emerged from the discussion.

* Keep authentication separate from authorisation.
* Keep ASP.NET Core Identity responsible for user identity.
* Keep Soteria responsible for application authorisation.
* Avoid global permissions when authority belongs to an individual client application.
* Allow one user to belong to multiple client applications.
* Build Phase 4 so that Phase 5 can introduce security without restructuring the user-management feature.
* Continue preferring explicit behaviour over hidden framework abstraction.
