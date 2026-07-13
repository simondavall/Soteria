This document describes the planned sequence of development for the project. It provides a high-level view of the intended implementation order and major milestones. Unlike the backlog, which records everything that could be done, the roadmap reflects what is expected to be done next.

# Phase 1 – Project Foundation

**Goal**

Establish the technical and architectural foundation that every later feature builds upon.

**Includes**

- ✓ Establish the user interface foundation using MudBlazor.
- ✓ Establish the project structure and feature organisation.
- ✓ Establish shared layouts and UI conventions.
- Migrate the built-in Identity user interface to the project's UI conventions.
- Integrate and configure the core infrastructure required by future authentication and authorisation features.
- Introduce shared UI components where proven through implementation.

**Deliverable**

A polished foundation that provides authentication through a consistent MudBlazor user interface and establishes the architecture for future development.

# Phase 2 – Client Application Management

**Goal**

Allow web applications to delegate authentication to Soteria.

**Includes**

- Register client applications.
- Configure OpenID Connect settings.
- Configure redirect URIs.
- Configure client authentication (for example, client secrets or PKCE where appropriate).
- Authenticate a consuming application using OpenID Connect.
- Enable or disable client applications.
- Manage application metadata.

**Deliverable**

A client application can be registered with Soteria and successfully authenticate users using OpenID Connect.

# Phase 3 – Identity Management

**Goal**

Provide central management of user identities.

**Includes**

- Create, edit, enable, and disable users.
- Search and manage users.
- Manage passwords.
- Manage email addresses.
- Account lockout.
- User self-service account management.
- Two-factor authentication.
- Additional identity management features as the project evolves.

**Deliverable**

Soteria can manage user identities independently of any consuming application.

# Phase 4 – Application Access Management

**Goal**

Control which users can access each client application and what authorisation information they receive.

**Includes**

- Grant and revoke application access.
- Manage application roles.
- Manage application claims.
- Manage application-specific authorisation information issued to consuming applications.
- Determine the authorisation information issued to client applications.
- Additional access management features as the project evolves.

**Deliverable**

Client applications trust Soteria as the source of truth for both authentication and authorisation.

# Future Enhancements

Future enhancements that fall outside the planned implementation phases will be recorded here as the project evolves.
