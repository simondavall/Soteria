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
9. Configure the Production environment variables.
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
| Application logs | `C:\ProgramData\Soteria\Logs` |

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

### 3.5 OpenIddict Issuer

The canonical OpenIddict issuer for the current Production deployment is:

```text
https://soteria.local
```

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
| Application log directory | Modify |
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

- `.env` is Development-only.
- It is loaded only after the application confirms it is running in Development.
- Existing process environment variables take precedence.
- `.env` is not included in publish output or Production deployment.

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

SMTP configuration is also supplied through environment variables.

Required values:

```
Soteria__Email__Host
Soteria__Email__Port
Soteria__Email__Security
Soteria__Email__DisplayName
Soteria__Email__SenderAddress
Soteria__Email__Username
Soteria__Email__Password
```

Development loads these values from the local `.env` file.

Production does not load `.env` files and must provide the values through the hosting environment.

### 5.4 Secrets and Credentials

Production OpenIddict credentials are provided through separate signing and
encryption certificates installed in the Windows Local Machine certificate store.

SMTP credentials are supplied through Production environment variables.

The SMTP host, mailbox address, username and password are deployment
configuration and are not committed to source control.

Development uses the local `.env` file for Development-only configuration,
including:

- OpenIddict Development encryption key.
- Reference Web client secret.
- SMTP configuration.

The `.env` file is never deployed to Production.

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

### 5.7 Production Logging

Soteria uses Serilog for Production application logging.

Production logs are stored at:

```text
C:\ProgramData\Soteria\Logs
```
The log directory is persistent operational state and is stored outside the
published application directory.

Logging uses:

- Readable text files.
- Structured message templates.
- Daily rolling.
- Additional size-based rolling.
- A 14-day retention period. 
- Information logging for Soteria application categories.
- Warning logging for framework categories unless a more specific override is configured.

Logs must not contain:

- Passwords.
- SMTP credentials.
- Client secrets.
- OpenIddict encryption keys.
- Certificate private-key material.
- Authorization codes.
- Access tokens.
- Refresh tokens.
- ID tokens.
- Password-reset codes or links.
- Account-confirmation links.
- Authentication cookies.
- Anti-forgery tokens.
- Complete request headers.
- Identity or OpenID Connect request bodies.

IIS ASP.NET Core Module stdout logging remains disabled during normal operation.

It may be enabled temporarily when diagnosing an application startup failure
that occurs before normal application logging becomes available. It must be
disabled again after troubleshooting because stdout logs are not subject to the
application log retention policy.

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

The initial deployment begins with no existing Production database.

The database is created by manually applying the Entity Framework Core
migrations to the configured SQLite database location.

No seed data is deployed with the application.

The initial database therefore contains only the schema required by the current
application version together with any data created by Entity Framework
migrations.

Following the initial deployment:

- The application starts normally.
- Entity Framework migrations have created the initial database schema.
- If no Soteria Administrator exists, the navigation menu displays `Register Soteria Administrator` above `Log in`.
- If one or more Soteria Administrators already exist, the `Register Soteria Administrator` option is not displayed.

Although no database exists during the initial deployment, the same migration
procedure is used for both first deployment and subsequent upgrades to maintain
a single repeatable operational process.

### 6.3 Applying Migrations

### 6.3 Applying Migrations

Entity Framework Core migrations are applied manually.

Automatic migration during application startup is intentionally not used.

This allows the database to be backed up immediately before any schema changes
are applied.

Migration procedure:

1. Stop the Soteria IIS Application Pool.
2. Verify the target database location.
3. If the database already exists, create a backup.
4. Apply the Entity Framework Core migrations. From the solution root execute:

   ```bash
   dotnet ef database update --project .\Soteria
   ```
5. Verify that the migration completed successfully.
6. Start the IIS Application Pool.
7. Verify successful application startup.

First deployment follows the same procedure except no backup is required because
no database yet exists.

If a migration fails, the application must not be started until the cause has
been investigated and corrected.

### 6.4 Backup

The SQLite database forms part of the persistent operational state of the
application.

A backup must be taken immediately before applying Entity Framework Core
migrations to an existing database.

The backup should consist of a complete copy of:

```text
C:\ProgramData\Soteria\Database\soteria.db
```
The backup must be retained until:

- the migration completes successfully;
- application startup has been verified;
- normal application operation has been confirmed.

### 6.5 Restore

If a deployment or migration fails after the database schema has been modified,
the database may be restored from the backup created immediately before the
migration.

Typical recovery procedure:

1. Stop the IIS Application Pool.
2. Replace the database with the backup copy.
3. Restore the corresponding application version if required.
4. Start the IIS Application Pool.
5. Verify successful application startup.

Database restoration does not affect:

- OpenIddict certificates;
- Data Protection keys;
- Production configuration;
- application log files.

Only the SQLite database is restored.

## 7. Deployment Procedure

### 7.1 Prepare the Host
### 7.2 Publish Soteria

To publish use the following from the solution root:

```bash
dotnet publish .\Soteria --configuration Release --output "C:\inetpub\wwwroot\Soteria"
```
- It is the currently verified deployment approach.
- It publishes directly into the live IIS directory.

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
- Required SMTP environment variables are configured.
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
- Account confirmation emails are delivered successfully.
- Password reset emails are delivered successfully.
- SMTP configuration validation succeeds.
- Production application log files are created.
- Routine application activity is recorded.
- Database schema version matches the deployed application.
- No pending Entity Framework Core migrations remain.

Verify administrator bootstrap behaviour:

- If no Soteria Administrator exists, the navigation menu displays
  `Register Soteria Administrator` above `Log in`.
- After the first administrator has been created, the
  `Register Soteria Administrator` menu option is no longer displayed.
- Existing Soteria Administrators can sign in normally.

## 8. Operational Procedures

### 8.1 Routine Deployment

To publish use the following from the solution root:

```bash
dotnet publish .\Soteria --configuration Release --output "C:\inetpub\wwwroot\Soteria"
```

- It is the currently verified deployment approach.
- It publishes directly into the live IIS directory.

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

This appendix provides the complete configuration template for the current
Production deployment.

Replace all placeholder values before starting the application.

### A.1 appsettings.Production.json

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=C:/ProgramData/Soteria/Database/soteria.db"
  },
  "OpenIddict": {
    "Certificates": {
      "SigningThumbprint": "<SIGNING_CERTIFICATE_THUMBPRINT>",
      "EncryptionThumbprint": "<ENCRYPTION_CERTIFICATE_THUMBPRINT>"
    },
    "Tokens": {
      "AccessTokenLifetimeMinutes": <ACCESS_TOKEN_LIFETIME_MINUTES>,
      "RefreshTokenLifetimeDays": <REFRESH_TOKEN_LIFETIME_DAYS>
    }
  }
}
```
A.2 Production Environment Variables

```
ASPNETCORE_ENVIRONMENT=Production

Soteria__Email__Host=<SMTP_HOST>
Soteria__Email__Port=<SMTP_PORT>
Soteria__Email__Security=<SMTP_SECURITY_MODE>
Soteria__Email__DisplayName=<SENDER_DISPLAY_NAME>
Soteria__Email__SenderAddress=<SENDER_EMAIL_ADDRESS>
Soteria__Email__Username=<SMTP_USERNAME>
Soteria__Email__Password=<SMTP_PASSWORD>
```

A.3 IIS Application Pool Environment Variables

For the current IIS deployment, configure the environment variables for the
Soteria application or Application Pool using the chosen IIS deployment
mechanism.

Do not commit populated Production values to source control.

After changing environment variables, restart the Soteria Application Pool so
that the worker process receives the new values.

A.4 Fixed Production Conventions

The following values are implementation conventions and are not currently
deployment-configurable:

| Setting | Value |
|----------|------------|
| Canonical URL	| https://soteria.local |
| Published application	| C:\inetpub\wwwroot\Soteria |
| SQLite database	| C:\ProgramData\Soteria\Database\soteria.db |
| Data Protection key ring	| C:\ProgramData\Soteria\DataProtection |
| Data Protection application name	| Soteria |
| Application logs	| C:\ProgramData\Soteria\Logs |
| Certificate store	| LocalMachine\My |
| IIS Application Pool	| Soteria |
| IIS identity	| IIS AppPool\Soteria |


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
        ├── DataProtection
        │   ├── key-xxxxxxxx.xml
        │   └── ...
        │
        └── Logs
            ├── soteria-yyyyMMdd.log
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

