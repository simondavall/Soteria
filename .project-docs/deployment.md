# Soteria Deployment Guide

## 1. Purpose

This document defines the deployment architecture and operational procedures for Soteria.

It records the agreed deployment architecture, operational procedures and
verification steps for the current implementation. The document is intended to
evolve alongside the project and become the authoritative operational guide for
deploying and maintaining Soteria.

---

## 2. Deployment Scope

The initial deployment targets a single-machine installation of Soteria for
development and evaluation purposes.

Current scope:

- Operating System: Windows 11 Pro
- Web Server: IIS
- Application URL: https://soteria.local
- Database: SQLite
- Database migrations applied manually
- Database backed up before migrations are applied
- Single Soteria application deployment
- Reference Web Application excluded
- Reference API excluded

Future phases may introduce support for additional deployment topologies,
database providers and production hosting environments.

---

## 3. Deployment Workflow

The current deployment process should be performed in the following order.

1. Install the required .NET runtime.
2. Configure IIS.
3. Create the IIS Application Pool.
4. Create the HTTPS certificate for `https://soteria.local`.
5. Configure the IIS HTTPS binding.
6. Install the OpenIddict signing certificate.
7. Install the OpenIddict encryption certificate.
8. Grant the IIS Application Pool access to both certificate private keys.
9. Configure the Production application settings.
10. Start the application.
11. Verify OpenIddict.
12. Verify Data Protection.
13. Perform post-deployment verification.

The remaining sections of this document provide the detailed procedures for each
step.

---

## 3. Deployment Architecture

### 3.1 Target Environment

The current deployment architecture consists of a single Windows machine hosting
both the Soteria application and its SQLite database.

Characteristics:

- Single server deployment
- Local IIS hosting
- Local SQLite database
- Local application storage
- HTTPS endpoint exposed via IIS
- No external infrastructure dependencies beyond the .NET runtime and IIS

This deployment model provides a simple baseline that can later be extended to
support larger or distributed production environments.

### 3.2 Hosting Model

The current deployment hosts Soteria as an ASP.NET Core application behind
Internet Information Services (IIS).

The hosting model consists of:

- IIS 10 or later.
- Dedicated IIS Website.
- Dedicated IIS Application Pool.
- No Managed Code application pool.
- Integrated request pipeline.
- HTTPS termination performed by IIS.
- ASP.NET Core Module V2 hosting the Soteria application.

The Application Pool is configured with:

| Setting | Value |
|---------|-------|
| Name | Soteria |
| .NET CLR | No Managed Code |
| Pipeline | Integrated |
| Identity | ApplicationPoolIdentity |
| Start Mode | AlwaysRunning |
| Idle Timeout | Disabled |
| Periodic Recycling | Disabled |

The application executes using the virtual account:

`IIS AppPool\Soteria`

This identity is granted access only to the resources required by the
application.

### 3.3 Directory Structure

The deployment separates published application files from persistent operational
state.

| Purpose | Location |
|---------|----------|
| Published application | `C:\inetpub\wwwroot\Soteria` |
| SQLite database | `C:\ProgramData\Soteria\Database` |
| Data Protection key ring | `C:\ProgramData\Soteria\DataProtection` |

This separation allows application updates to replace the published binaries
without affecting authentication state or persisted application data.

### 3.4 Network Topology

The current deployment exposes a single HTTPS endpoint.

| Setting | Value |
|---------|-------|
| Hostname | `soteria.local` |
| Protocol | HTTPS |
| Port | 443 |

The IIS binding uses Server Name Indication (SNI) to support future coexistence
with additional HTTPS websites.

The current deployment is intended for local development and evaluation.

Future production deployments may replace the hostname with an externally
accessible domain.


## 4. Prerequisites

### 4.1 Software
### 4.2 IIS Features
### 4.3 .NET Runtime
### 4.4 Certificates

Soteria uses dedicated OpenIddict certificates in Production.

Two independent RSA certificates are required:

- Signing certificate
- Encryption certificate

Requirements:

- Installed into the Windows **Local Machine → Personal (My)** certificate store.
- Include private keys.
- Valid for the deployment period.
- Accessible to the IIS Application Pool identity.
- Separate certificates must be used for signing and encryption.

Development credentials are never used outside the Development environment.

### 4.5 Required Accounts and Permissions

The deployment requires no dedicated Windows service account.

The IIS Application Pool identity is used throughout.

Required permissions are summarised below.

| Resource | Permission |
|----------|------------|
| Published application | Read & Execute |
| SQLite database directory | Modify |
| Data Protection directory | Modify |
| OpenIddict Signing certificate private key | Read |
| OpenIddict Encryption certificate private key | Read |

No additional local administrator permissions are required once deployment has
completed.


## 5. Configuration

### 5.1 Configuration Sources

The current implementation uses the following configuration sources.

| Source | Purpose |
|---------|---------|
| `appsettings.json` | Default application configuration. |
| `appsettings.{Environment}.json` | Environment-specific configuration overrides. |
| Environment variables | Secrets and deployment-specific configuration. |
| Local `.env` file | Development environment variables loaded during local execution. |
| `launchSettings.json` | Local development launch profile only. Not used for deployed environments. |

The application does not currently use ASP.NET Core User Secrets.

No additional application-specific configuration sources currently exist.

### 5.2 Application Settings

The following application settings are required for deployment.

#### appsettings.json

Contains environment-independent application configuration.

#### appsettings.Production.json

Contains Production-specific configuration.

Current OpenIddict configuration:

```json
{
  "OpenIddict": {
    "Certificates": {
      "SigningThumbprint": "<Signing Certificate Thumbprint>",
      "EncryptionThumbprint": "<Encryption Certificate Thumbprint>"
    },
    "Tokens": {
      "AccessTokenLifetimeMinutes": <Duration>,
      "RefreshTokenLifetimeDays": <Duration>
    }
  }
}
```

Certificate thumbprints identify certificates installed in the Windows
Local Machine certificate store.
Configure OpenIddict token lifetime settings appropriate for the deployment.

Current Data Protection configuration:

| Setting | Value |
|---------|-------|
| Key ring location | `C:\ProgramData\Soteria\DataProtection` |
| Key protection | Windows DPAPI (Local Machine) |
| Application name | `Soteria` |

The Data Protection key ring location is an implementation convention and is
not currently configurable.

The directory is created automatically on application startup if it does not
already exist and the application has sufficient permissions.

### 5.3 Environment Variables

Production deployments must configure:

```
ASPNETCORE_ENVIRONMENT=Production
```

The Development environment uses:

```
ASPNETCORE_ENVIRONMENT=Development
```

Credential selection is performed automatically based on the current environment.

Current Production deployments also require:

```
OpenIddict__EncryptionKey
```

This value exists as a legacy compatibility requirement while the application
continues to validate the existing symmetric encryption configuration.

This dependency is expected to be removed once the Production implementation
relies solely on certificate-based encryption.

### 5.4 Secrets

Deployment secrets are supplied through Windows Environment Variables.

Application configuration intentionally separates deployment configuration from
secret material.

Production secrets are therefore not committed to source control or stored in
application configuration files.

The current implementation uses:

- OpenIddict certificate thumbprints stored in configuration.
- Secret values supplied through Environment Variables.

The long-term objective is to minimise the number of required deployment
secrets through increased use of certificate-based authentication.

### 5.5 Data Protection

Soteria uses ASP.NET Core Data Protection to protect authentication cookies,
anti-forgery tokens and other framework-protected data.

#### Development

Development uses the default ASP.NET Core Data Protection behaviour.

No persistent key-ring configuration is required.

#### Production

Production uses:

- Persistent file-system key storage.
- Key ring stored in:

  `C:\ProgramData\Soteria\DataProtection`

- Windows DPAPI (Local Machine) protection.
- Application discriminator:

  `Soteria`

The key ring is stored outside the published application directory so that
authentication cookies remain valid across:

- Application restart
- IIS application pool recycle
- Application redeployment

The Data Protection directory forms part of the persistent operational state of
the application and should not be removed during normal deployments.

### 5.6 OpenIddict Credentials

Credential registration is environment specific.

#### Development

Development uses:

- OpenIddict Development Signing Certificate.
- Symmetric encryption key from configuration.

This behaviour is unchanged from the original OpenIddict implementation.

#### Production

Production uses:

- Signing certificate loaded from the Windows Local Machine certificate store.
- Encryption certificate loaded from the Windows Local Machine certificate store.

Startup validation verifies:

- Signing thumbprint configured.
- Encryption thumbprint configured.
- Thumbprints have a valid format.
- Certificates exist.
- Certificates contain private keys.
- Certificates are currently valid.
- Certificates support RSA.
- Signing and encryption certificates are different.

Deployment fails immediately if any validation fails.


## 6. Database

### 6.1 Database Location

The Production SQLite database is stored at:

```
C:\ProgramData\Soteria\Database\soteria.db
```

The database is intentionally stored outside the published application
directory.

Redeploying the application must not replace or recreate this database.

### 6.2 First Deployment
### 6.3 Applying Migrations
### 6.4 Backup
### 6.5 Restore

## 7. Deployment Procedure

### 7.1 Prepare the Host
### 7.2 Publish Soteria
### 7.3 Configure IIS
### 7.4 Configure Application

Before starting the application verify:

- OpenIddict Signing certificate installed.
- OpenIddict Encryption certificate installed.
- Certificate thumbprints configured.
- IIS Application Pool has Read access to both certificate private keys.
- SQLite database directory exists.
- Data Protection directory exists.
- IIS Application Pool has Modify permission to both persistent directories.
- Required Production Environment Variables are configured.
- ASPNETCORE_ENVIRONMENT is set to `Production`.

### 7.5 Start the Application
### 7.6 Verify Deployment

Verify:

- Application starts successfully.
- No startup validation errors occur.
- Discovery document is available.
- Authorisation endpoint responds.
- Token endpoint responds.
- Access tokens are successfully issued.
- Access tokens are digitally signed.
- Access tokens are encrypted.
- Refresh-token flow succeeds.
- Data Protection key ring directory exists.
- Data Protection keys are created successfully.
- Authentication survives Application Pool recycling.
- Authentication survives IIS restart.
- SQLite database persists across application redeployment.


## 8. Operational Procedures

### 8.1 Routine Deployment
### 8.2 Upgrading

Routine upgrades replace only the published application files.

The following operational data must be preserved:

- SQLite database.
- Data Protection key ring.
- OpenIddict certificates.
- HTTPS certificate.
- Production configuration.

Successful upgrades should not require users to authenticate again and should
not affect persisted application data.

### 8.3 Rollback
### 8.4 Certificate Renewal
### 8.5 Secret Rotation

## 9. Verification

### 9.1 Platform Verification
### 9.2 Identity Verification
### 9.3 OpenIddict Verification

Verify the following:

- Discovery metadata is available.
- Authorisation Code flow succeeds.
- Refresh-token flow succeeds.
- Access tokens are signed.
- Access tokens are encrypted.
- Startup validation rejects invalid certificate configurations.

### 9.4 Security Verification

Verify the following:

- Data Protection key files are stored outside the application publish directory.
- Data Protection keys are protected using Windows DPAPI.
- Authentication cookies remain valid after application restart.
- Authentication cookies are invalidated if the key ring is intentionally removed.


## 10. Troubleshooting

## 11. Known Limitations

## 12. Future Enhancements

## Appendix A - Configuration Reference

## Appendix B - Directory Layout

```
C:\
├── inetpub
│   └── wwwroot
│       └── Soteria
│           ├── Soteria.exe
│           ├── web.config
│           ├── *.dll
│           └── wwwroot
│
└── ProgramData
    └── Soteria
        ├── Database
        │   └── soteria.db
        │
        └── DataProtection
            ├── key-xxxxxxxx.xml
            └── ...
```

## Appendix C - Deployment Checklist

### Data Protection

- [ ] Data Protection directory created.
- [ ] IIS Application Pool has Modify permission.
- [ ] Key ring created after first startup.
- [ ] Authentication persists after application restart.

## Appendix D - Recovery Checklist

### Data Protection Key Ring

If the Data Protection key ring is lost:

- Existing authentication cookies become invalid.
- Existing anti-forgery tokens become invalid.
- Protected ASP.NET Core payloads become unreadable.

Application and database data are not affected.

If a backup of the key ring is available:

- Restore the key files.
- Restart the application.

Otherwise:

- Allow users to authenticate again.

