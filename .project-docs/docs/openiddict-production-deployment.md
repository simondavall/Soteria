# Production OpenIddict Certificate Deployment

## Purpose

Soteria uses two dedicated OpenIddict certificates in Production:

- **Signing Certificate** – Used to digitally sign issued tokens.
- **Encryption Certificate** – Used to encrypt issued tokens.

Both certificates are loaded from the Windows **Local Machine → Personal (My)** certificate store using their configured thumbprints.

Development credentials are never used outside the Development environment.

---

# Prerequisites

Before deployment ensure the target server has:

- Windows 11 Pro with IIS installed.
- Soteria application published.
- Administrator access to the server.
- Two RSA certificates:
    - Signing certificate.
    - Encryption certificate.
- Both certificates include their private keys.

---

# Certificate Installation

## Signing Certificate

1. Open **Microsoft Management Console (MMC)**.
2. Add the **Certificates** snap-in for the **Local Computer**.
3. Navigate to:

   ```
   Certificates (Local Computer)
       Personal
           Certificates
   ```

4. Import the signing certificate including its private key.
5. Verify:
    - The certificate appears in the Personal store.
    - A private key is present ("You have a private key...").
    - The certificate is valid.
6. Record the certificate thumbprint.

---

## Encryption Certificate

Repeat the same process for the encryption certificate.

Verify that:

- The certificate is installed into the same **Local Machine → Personal** store.
- The certificate contains its private key.
- The certificate is valid.
- The thumbprint has been recorded.

---

# Record Certificate Thumbprints

Open the certificate properties.

On the **Details** tab locate:

```
Thumbprint
```

Copy the thumbprint value.

> **Note**
>
> Windows often inserts hidden whitespace when copying certificate thumbprints. Soteria automatically removes whitespace during startup, but it is still recommended to paste the value into a text editor first and confirm it contains only hexadecimal characters.

---

# Configure Soteria

Configure the production certificate thumbprints in:

`appsettings.Production.json`

```json
{
  "OpenIddict": {
    "Certificates": {
      "SigningThumbprint": "<Signing Certificate Thumbprint>",
      "EncryptionThumbprint": "<Encryption Certificate Thumbprint>"
    }
  }
}
```

Do **not** configure:

- Certificate passwords
- PFX file paths
- Certificate store names
- Certificate locations

Soteria always loads certificates from:

```
LocalMachine\My
```

---

# IIS Private Key Permissions

The IIS Application Pool identity must be granted **Read** access to both certificate private keys.

For each certificate:

1. Open **Certificates (Local Computer)**.
2. Locate the certificate.
3. Right-click.
4. Select:

```
All Tasks
    Manage Private Keys...
```

5. Add the application pool identity:

```
IIS AppPool\<ApplicationPoolName>
```

6. Grant:

- Read

permission only.

Repeat this process for both the signing and encryption certificates.

---

# IIS Configuration

Verify the Production environment is correctly configured.

- `ASPNETCORE_ENVIRONMENT=Production`
- HTTPS binding configured.
- Correct Application Pool identity.
- Application Pool has access to both certificate private keys.

Recycle the Application Pool after changing certificate permissions or configuration.

---

# Startup Validation

During application startup Soteria validates the complete production certificate configuration.

Startup will fail immediately if any of the following conditions are detected:

- Signing certificate thumbprint missing.
- Encryption certificate thumbprint missing.
- Invalid thumbprint format.
- Certificate not found.
- Certificate has no private key.
- Certificate is not yet valid.
- Certificate has expired.
- Certificate is not RSA.
- Signing and encryption certificates are the same certificate.

Each failure produces a descriptive startup exception to simplify deployment troubleshooting.

---

# Deployment Verification Checklist

## Development Verification

Verify the existing Development behaviour remains unchanged.

- Application starts successfully.
- Development signing certificate is registered.
- Development symmetric encryption key is registered.
- Login succeeds.
- Authorization Code flow succeeds.
- Refresh token flow succeeds.

---

## Production Startup Verification

Verify:

- Application starts successfully.
- No startup exceptions occur.
- Signing certificate loads successfully.
- Encryption certificate loads successfully.

---

## Production Token Verification

Obtain an Authorization Code and exchange it for an access token.

Verify:

- Token issued successfully.
- Token is digitally signed.
- Token encryption succeeds.
- Refresh token flow succeeds.

---

## Failure Verification

Confirm startup fails when:

- Signing certificate is removed.
- Encryption certificate is removed.
- Signing private key is unavailable.
- Encryption private key is unavailable.
- Expired certificate is configured.
- Not-yet-valid certificate is configured.
- Same certificate configured for signing and encryption.

Each scenario should fail during application startup with a clear diagnostic message.

---

# Operational Notes

- Use separate certificates for signing and encryption.
- Replace certificates before expiry.
- Never deploy development credentials to Production.
- Certificates are always loaded from the Windows **Local Machine → Personal (My)** certificate store.
- IIS Application Pool identities require **Read** access to both certificate private keys.
- Certificate thumbprints are treated as case-insensitive and whitespace is ignored during startup.