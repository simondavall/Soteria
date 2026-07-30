# Phase 1 – Application Foundation

**Goal**

Establish the technical, architectural and presentation foundation for Soteria.

**Includes**

- ✓ Establish the project structure and feature organisation.
- ✓ Add and configure MudBlazor.
- ✓ Establish the shared application layout and UI conventions.
- ✓ Migrate the built-in ASP.NET Core Identity UI to the project UI conventions.
- ✓ Preserve the ASP.NET Core Identity behaviour and static SSR workflows.
- ✓ Establish proven implementation patterns for Identity workflows.

**Deliverable**

Soteria provides a consistent MudBlazor user experience while preserving the behaviour of the built-in ASP.NET Core Identity implementation.

---

# Phase 2 – OpenID Connect Provider Foundation

**Goal**

Enable Soteria to act as an OpenID Connect Provider capable of authenticating a consuming web application.

**Includes**

- ✓ Establish the OpenID Connect provider architecture.
- ✓ Create reference web and API applications.
- ✓ Configure the OpenIddict provider.
- ✓ Establish development signing and encryption credentials.
- ✓ Support Authorization Code Flow with PKCE.
- ✓ Register an initial development client.
- ✓ Establish the initial scopes and claims.
- ✓ A consuming application can authenticate users through Soteria and securely access protected APIs using OAuth-issued access tokens.

**Deliverable**

A consuming web application can successfully authenticate users through Soteria using OpenID Connect and securely access a protected resource API using OAuth-issued JWT access tokens.

---

# Phase 3 – Client Application Management

**Goal**

Allow administrators to manage applications that delegate authentication to Soteria.

**Includes**

- ✓ Register client applications.
- ✓ Configure redirect URIs.
- ✓ Configure client authentication.
- ✓ Configure OpenID Connect settings.
- ✓ Enable or disable client applications.

**Deliverable**

Client applications can be managed through Soteria and successfully authenticate users.

---

# Phase 4 – Identity Management

**Goal**

Provide central administration of user identities.

**Includes**

- ✓ Create & edit users.
- ✓ Search and manage users.
- ✓ Reset account lockout.

**Deliverable**

Soteria manages user identities independently of consuming applications.

---

# Phase 5 – Application Access Management

**Goal**

Control which users can access each client application and what authorisation information they receive.

**Includes**

- ✓ Grant and revoke application access.
- ✓ Manage application roles.
- Manage application claims.
- Determine the authorisation information issued to client applications.
- Additional access management features as the project evolves.

**Deliverable**

Client applications trust Soteria as the source of truth for both authentication and authorisation.

---

# Phase 6 - Extended Application Configuration

Allow other client types and permissions.

---

# Future Enhancements

Future enhancements outside the planned implementation phases will be recorded here as the project evolves.