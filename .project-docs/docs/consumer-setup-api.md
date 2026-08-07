# Soteria Web API Consumer Setup

## 1. Purpose

This document defines the minimum configuration required to integrate an ASP.NET
Core Web API with a Production Soteria instance.

Following this document will produce a Web API that:

* accepts access tokens issued by Soteria;
* validates the Soteria issuer and API audience;
* decrypts Production access tokens;
* exposes authenticated endpoints; and
* supports role-based authorisation using Application Role claims.

---

## 2. Application Configuration

Add the Soteria authority and Production encryption certificate thumbprint to
the API configuration.

```json
{
  "Authentication": {
    "Authority": "https://soteria.local"
  },
  "OpenIddict": {
    "EncryptionCertificateThumbprint": "<ENCRYPTION_CERTIFICATE_THUMBPRINT>"
  }
}
```

The following values are required:

```text
Authentication:Authority
OpenIddict:EncryptionCertificateThumbprint
```

The authority must identify the Production Soteria instance:

```text
https://soteria.local
```

The encryption certificate thumbprint must identify the same OpenIddict
encryption certificate used by Soteria to encrypt access tokens.

The certificate must be installed in:

```text
LocalMachine\My
```

The Web API process identity must have Read permission to the certificate private
key.

---

## 3. Configure Authentication

Read and validate the configured Soteria authority:

```csharp
var authority =
    builder.Configuration["Authentication:Authority"]
    ?? throw new InvalidOperationException(
        "The Authentication:Authority configuration value is required.");
```

Configure OpenIddict validation as the default authentication scheme:

```csharp
using OpenIddict.Validation.AspNetCore;

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme =
            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;

        options.DefaultChallengeScheme =
            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
    });
```

Configure OpenIddict token validation:

```csharp
builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        options.SetIssuer(authority);

        options.AddAudiences("<API_SCOPE>");

        var encryptionCertificate =
            LoadProductionEncryptionCertificate(
                builder.Configuration);

        options.AddEncryptionCertificate(
            encryptionCertificate);

        options.Configure(validationOptions =>
        {
            validationOptions.TokenValidationParameters.RoleClaimType =
                "role";

            validationOptions.TokenValidationParameters.NameClaimType =
                "name";
        });

        options.UseSystemNetHttp();
        options.UseAspNetCore();
    });
```

Replace:

```text
<API_SCOPE>
```

with the audience assigned to the API.

For the Reference API this value is:

```text
reference_api
```

The configured audience must match the resource associated with the scope
requested by the consuming web application.

---

## 4. Load the Encryption Certificate

Add the following certificate-loading methods to `Program.cs`.

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

static X509Certificate2 LoadProductionEncryptionCertificate(
    IConfiguration configuration)
{
    var configuredThumbprint =
        configuration[
            "OpenIddict:EncryptionCertificateThumbprint"];

    if (string.IsNullOrWhiteSpace(configuredThumbprint))
    {
        throw new InvalidOperationException(
            "The OpenIddict:EncryptionCertificateThumbprint " +
            "configuration value is required in Production.");
    }

    var thumbprint =
        NormalizeCertificateThumbprint(
            configuredThumbprint);

    using var store =
        new X509Store(
            StoreName.My,
            StoreLocation.LocalMachine);

    store.Open(OpenFlags.ReadOnly);

    var certificates =
        store.Certificates.Find(
            X509FindType.FindByThumbprint,
            thumbprint,
            validOnly: false);

    var certificate =
        certificates
            .OfType<X509Certificate2>()
            .SingleOrDefault();

    if (certificate is null)
    {
        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with " +
            $"thumbprint '{thumbprint}' was not found in " +
            $"LocalMachine\\My.");
    }

    if (!certificate.HasPrivateKey)
    {
        certificate.Dispose();

        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with " +
            $"thumbprint '{thumbprint}' does not contain an " +
            $"accessible private key.");
    }

    if (certificate.NotBefore.ToUniversalTime() >
        DateTime.UtcNow)
    {
        certificate.Dispose();

        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with " +
            $"thumbprint '{thumbprint}' is not yet valid.");
    }

    if (certificate.NotAfter.ToUniversalTime() <=
        DateTime.UtcNow)
    {
        certificate.Dispose();

        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with " +
            $"thumbprint '{thumbprint}' has expired.");
    }

    using var rsaPrivateKey =
        certificate.GetRSAPrivateKey();

    if (rsaPrivateKey is null)
    {
        certificate.Dispose();

        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with " +
            $"thumbprint '{thumbprint}' does not provide an " +
            $"RSA private key.");
    }

    return certificate;
}

static string NormalizeCertificateThumbprint(
    string thumbprint)
{
    var normalized =
        new string(
            thumbprint
                .Where(character =>
                    !char.IsWhiteSpace(character))
                .ToArray());

    if (normalized.Length == 0 ||
        normalized.Any(character =>
            !Uri.IsHexDigit(character)))
    {
        throw new InvalidOperationException(
            "The OpenIddict:EncryptionCertificateThumbprint " +
            "configuration value must contain a hexadecimal " +
            "certificate thumbprint.");
    }

    return normalized;
}
```

This configuration validates that the certificate:

* exists in the Local Machine certificate store;
* contains an accessible private key;
* is currently valid; and
* provides an RSA private key.

---

## 5. Configure Authorisation

Add the application authorisation policies required by the API.

Example:

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(
        "Editor",
        policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireRole("Editor");
        });

    options.AddPolicy(
        "Auditor",
        policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireRole("Auditor");
        });

    options.AddPolicy(
        "EditorOrReviewer",
        policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireRole(
                "Editor",
                "Reviewer");
        });
});
```

The role names must match the Application Role names issued by Soteria.

Application Role claims are read using:

```text
role
```

The authenticated user's display name is read using:

```text
name
```

---

## 6. Configure the Request Pipeline

Add authentication before authorisation:

```csharp
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();
```

Authentication must run before protected endpoints are mapped or executed.

---

## 7. Protect API Endpoints

Require authentication for endpoints that accept any valid Soteria access
token:

```csharp
app.MapGet(
        "/api/example",
        () => Results.Ok(
            new
            {
                Message = "The protected API is reachable."
            }))
    .RequireAuthorization();
```

Require a specific Application Role policy where needed:

```csharp
app.MapGet(
        "/api/editor",
        (ClaimsPrincipal user) =>
            Results.Ok(
                new
                {
                    Message =
                        $"Editor access granted to " +
                        $"{user.Identity?.Name}."
                }))
    .RequireAuthorization("Editor");
```

An endpoint can accept more than one role through a named policy:

```csharp
app.MapGet(
        "/api/review",
        () => Results.Ok())
    .RequireAuthorization(
        "EditorOrReviewer");
```

Requests without a valid access token are rejected with:

```text
401 Unauthorized
```

Requests with a valid token but without the required role are rejected with:

```text
403 Forbidden
```

---

## 8. Verification

Verify the following after completing the setup:

* [ ] The API starts successfully in Production.
* [ ] The Soteria authority is configured as `https://soteria.local`.
* [ ] The API audience matches the configured Soteria API scope.
* [ ] The OpenIddict encryption certificate is installed in `LocalMachine\My`.
* [ ] The API process identity can read the certificate private key.
* [ ] A request without an access token is rejected.
* [ ] A request with an invalid access token is rejected.
* [ ] A valid Soteria access token is accepted.
* [ ] The authenticated user's name is available.
* [ ] Application Role claims are available as roles.
* [ ] Role-protected endpoints allow authorised users.
* [ ] Role-protected endpoints reject users without the required role.
