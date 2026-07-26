# Soteria Phase 5 Authorisation Architecture

> **Status:** Architectural reference
>
> This document defines the agreed Phase 5 authorisation architecture for Soteria. It records the agreed design and the minimum implementation guidance required to understand and implement the model.

---

# Purpose

ASP.NET Core Identity is responsible for authentication and identity management.

Soteria is responsible for application access, delegated administration, application roles and claim issuance.

Identity determines **who the user is**.

Soteria determines **what the user may do**.

---

# Responsibility Model

## ASP.NET Core Identity

Responsible for:

- User accounts
- Authentication
- Passwords
- Email confirmation
- Lockout
- Two-factor authentication
- Account recovery

## Soteria

Responsible for:

- Client applications
- Client membership
- System roles
- Application roles
- Claim issuance
- Authorisation decisions

---

# Authority Model

## System Roles

System Roles define global authority within Soteria.

Initially:

- Soteria Administrator

System Roles:

- authorise Soteria administration;
- never grant client access;
- are never issued to consuming applications.

## Client Membership

A Client Membership grants access to one client application.

Membership records:

- Membership Level
- Assigned Application Roles

Membership Levels:

- User
- Administrator

Constraints:

- unique(UserId, ApplicationId)

Removing a membership removes access to that client and its application-role assignments.

## Application Roles

Application Roles belong to a single client application.

Role names are permission-oriented, for example:

- Reports.View
- Reports.Edit
- Orders.Approve

`Name` is the stable value used for claims and policies.

`DisplayName` is used only within Soteria.

Constraints:

- unique(ApplicationId, Name)

---

# User Categories

## Soteria Administrator

May:

- manage users;
- manage client applications;
- assign System Roles;
- manage all client memberships;
- assign application roles.

A System Role does not automatically grant access to consuming applications.

## Client Administrator

Represented by:

- MembershipLevel = Administrator

May administer only the client applications they belong to.

May:

- register users;
- manage client membership;
- appoint additional Client Administrators;
- assign Application Roles;
- clear account lockout.

Cannot modify ASP.NET Core Identity account data other than supported administration operations.

## Client User

May manage only their own Identity account using the standard Identity pages.

---

# Registration Model

Registration is an administrative workflow.

Users do not self-register.

Creating a user:

- create the Identity account if it does not exist;
- create one or more Client Memberships;
- send an email confirmation link;
- require password change on first use.

If the email already exists:

- reuse the existing Identity account;
- add new Client Memberships only.

One Identity account may belong to multiple client applications.

---

# Visibility Rules

Client Administrators may only view and manage users belonging to client applications they administer.

They must not see memberships or administration data belonging to unrelated client applications.

---

# Persistence Model

## System Roles

```text
SystemRole
    Id
    Name
    DisplayName
    Description

UserSystemRole
    UserId
    SystemRoleId
```

## Client Membership

```text
ClientMembership
    Id
    UserId
    ApplicationId
    MembershipLevel
    CreatedUtc
```

## Application Roles

```text
ApplicationRole
    Id
    ApplicationId
    Name
    DisplayName
    Description
```

## Application Role Assignments

```text
ClientMembershipApplicationRole
    ClientMembershipId
    ApplicationRoleId
```

## Relationships

```text
ApplicationUser
    ├── UserSystemRoles
    └── ClientMemberships

SystemRole
    └── UserSystemRoles

SoteriaApplication
    ├── ClientMemberships
    └── ApplicationRoles

ClientMembership
    └── ApplicationRoleAssignments
```

## Deletion

- Removing Client Membership removes role assignments.
- Removing a user removes memberships, role assignments and System Role assignments.
- Client applications should normally be disabled rather than deleted.

The model should remain compatible with future audit fields.

---

# Claim Design

Only Application Roles are issued to consuming applications.

System Roles and Membership Levels remain internal to Soteria.

## ID Token

Typical claims:

- sub
- name
- preferred_username
- email

Application Role claims may be included where required.

## Access Token

Typical claims:

- sub
- aud
- scope
- role

Only roles belonging to the requesting client application are issued.

Protected APIs authorise using Application Role claims.

Named policies are preferred over embedded role strings.

During refresh-token redemption:

- revalidate Client Membership;
- reload current Application Roles;
- reject if membership has been removed.

---

# Authorisation Flow

1. Validate client.
2. Authenticate user.
3. Load Client Membership.
4. Reject if no membership exists.
5. Load Application Roles.
6. Issue claims.
7. Issue tokens.

---

# Enforcement Model

## Client Validation

Validate the client and confirm it is enabled.

## Authorisation Request

- authenticate the user;
- load Client Membership;
- reject if no membership exists;
- load current Application Roles.

## Authorisation Code Redemption

Revalidate Client Membership and reload current Application Roles before issuing tokens.

## Refresh Token Redemption

Revalidate Client Membership.

Reload current Application Roles.

Reject the request if membership has been removed.

## Soteria Administration

- System Roles authorise global administration.
- Membership Level authorises delegated client administration.
- Services enforce client scope and must not rely solely on UI authorisation.

---

# Phase Boundaries

## Phase 4

Implements Identity management and administration pages.

## Phase 5

Implements:

- Client Membership
- System Roles
- Application Roles
- Claim issuance
- Authorisation enforcement

---

# Remaining Open Questions

- Future delegated administration capabilities.
- Governance, audit history and token revocation.

---

# Design Principles

- Separate authentication from authorisation.
- Identity owns identity.
- Soteria owns application access.
- Keep System Roles separate from Client Membership.
- Keep Client Membership separate from Application Roles.
- Administrative authority does not imply application access.
- Every authorisation decision begins with Client Membership.
- Only roles belonging to the requesting client are issued.
