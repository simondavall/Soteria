# Consumer Setup.

# Soteria Web Application Consumer Setup

## 1. Purpose

This document defines the minimum configuration required to integrate an ASP.NET
Core web application with a deployed Soteria instance.

Following this document will produce a web application that:

- authenticates users using Soteria;
- maintains a local ASP.NET Core authentication cookie;
- supports authenticated and anonymous pages;
- supports application sign-in and sign-out; and
- is ready to call protected APIs using the authenticated user's access token.

---

## 2. Application Configuration

Configure the application to use the deployed Soteria instance.

### appsettings.json

```json
{
  "Authentication": {
    "OpenIdConnect": {
      "Authority": "https://soteria.local",
      "ClientId": "<ClientId>"
    }
  }
}
```

Configure the client secret using the application's Production configuration.

The following configuration values are required:

- Authentication:OpenIdConnect:Authority
- Authentication:OpenIdConnect:ClientId
- Authentication:OpenIdConnect:ClientSecret

---

## 3. Authentication Configuration

Configure the application to use:

- ASP.NET Core Cookie Authentication
- ASP.NET Core OpenID Connect Authentication

Configure OpenID Connect with:

- Authorization Code Flow
- PKCE enabled
- Token persistence enabled
- Inbound claim mapping disabled

Request the following scopes:

- openid
- profile
- email
- offline_access
- reference_api

Configure the authentication middleware:

```text
UseAuthentication()

UseAuthorization()
```

Configure the application to:

- challenge using the OpenID Connect authentication scheme;
- maintain a local authentication cookie after successful authentication; and
- configure the Name and Role claim types as:

```text
name
role
```

---

## 4. Authentication UI

Provide a Login action that challenges the OpenID Connect authentication scheme.

Provide a Logout action that signs out of both:

- the local authentication cookie; and
- the OpenID Connect session.

Protect application pages using standard ASP.NET Core authorisation.

Example:

```csharp
[Authorize]
```

or

```razor
<AuthorizeView>
```

Configure application-specific authorisation policies where required.

---

## 5. Verification

Verify the following after completing the configuration.

- [ ] The Login action redirects to Soteria.
- [ ] Authentication succeeds.
- [ ] The application returns to the requested page.
- [ ] A local authentication cookie is created.
- [ ] Protected pages require authentication.
- [ ] Authenticated users can access protected pages.
- [ ] Logout removes the local authentication session.