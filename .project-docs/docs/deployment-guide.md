# Soteria Deployment Guide

**Version:** 1.0  
**Status:** Current  
**Target Environment:** Windows Server / Windows 11 with IIS 10+ and .NET 10

---

# 1. Overview

## 1.1 Purpose

This document describes the complete deployment procedure for a Production instance of Soteria hosted on Internet Information Services (IIS).

The guide has been produced from a successful end-to-end deployment of Soteria and provides a verified sequence of tasks, PowerShell commands, configuration changes, troubleshooting guidance and verification steps.

Following this guide should result in a fully functioning Production deployment without requiring additional documentation.

---

## 1.2 Scope

This guide covers:

- Installing the .NET Hosting Bundle
- Configuring IIS
- Creating the IIS Application Pool
- Creating the IIS Website
- Configuring HTTPS
- Installing and configuring OpenIddict certificates
- Configuring Data Protection
- Configuring the SQLite database
- Publishing the application
- Applying Entity Framework Core migrations
- Performing the initial Production startup
- Troubleshooting startup failures
- Verifying the deployment
- Redeploying future versions

---

## 1.3 Deployment Architecture

Soteria separates application binaries from operational data.

| Component | Location |
|-----------|----------|
| Application | `C:\inetpub\wwwroot\Soteria` |
| SQLite Database | `C:\ProgramData\Soteria\Database` |
| Data Protection Keys | `C:\ProgramData\Soteria\DataProtection` |

This layout ensures that application deployments do not overwrite operational state.

---

## 1.4 Certificates

A Production deployment uses three independent certificates.

| Certificate | Purpose |
|------------|---------|
| Soteria HTTPS | HTTPS communication between browser and IIS |
| Soteria OpenIddict Signing | Signs OpenIddict tokens |
| Soteria OpenIddict Encryption | Encrypts OpenIddict tokens |

Each certificate has a different purpose and must not be reused for another role.

---

# 2. Deployment Workflow

Deployment should always follow the sequence below.

Skipping steps or performing them in a different order may require unnecessary reconfiguration.

1. Install the .NET Hosting Bundle.
2. Configure IIS.
3. Create the deployment directories.
4. Configure the Application Pool.
5. Create the IIS Website.
6. Configure HTTPS.
7. Install the OpenIddict certificates.
8. Configure certificate permissions.
9. Configure Data Protection.
10. Configure the SQLite database.
11. Publish the application.
12. Apply database migrations.
13. Perform the first Production startup.
14. Verify the deployment.

The remaining sections of this document provide the detailed procedure for each stage.

---

# 3. Prerequisites

Before deployment ensure the following software is available.

| Requirement | Version |
|------------|---------|
| Windows | Windows 11 or Windows Server 2022 or later |
| IIS | Version 10 or later |
| .NET | .NET 10 Hosting Bundle |
| PowerShell | 7.x (recommended) or Windows PowerShell 5.1 |
| Certificate Store | LocalMachine |
| Database | SQLite |

Administrative privileges are required throughout the deployment.

---

## 3.1 Verify Existing .NET Installation

Open an elevated PowerShell session.

Run:

```powershell
dotnet --info
```

Run:

```powershell
dotnet --list-runtimes
```

### Verification

The installed runtimes should include entries similar to:

```text
Microsoft.NETCore.App 10.x.x
Microsoft.AspNetCore.App 10.x.x
```

Older .NET runtimes may remain installed and do not need to be removed.

---

## 3.2 Verify Existing Hosting Bundle

Open:

```
Settings
→ Apps
→ Installed Apps
```

Search for:

```
Hosting
```

If an earlier Hosting Bundle is installed it may remain in place.

The current .NET 10 Hosting Bundle will be installed during deployment.

---

# 4. Install the .NET Hosting Bundle

## 4.1 Download

Download the latest **.NET 10 Hosting Bundle** from Microsoft's official download page.

Install the **Hosting Bundle**, not:

- .NET Runtime
- ASP.NET Runtime
- Desktop Runtime
- SDK

---

## 4.2 Install

Run the installer as Administrator.

Complete the installation.

If the installer offers **Repair**, select **Repair**.

---

## 4.3 Restart IIS

After installation restart IIS.

```powershell
net stop was /y
net start w3svc
```

A system restart may be used instead.

---

## 4.4 Verify Installation

Run:

```powershell
dotnet --list-runtimes
```

Expected:

```text
Microsoft.NETCore.App 10.x.x
Microsoft.AspNetCore.App 10.x.x
```

Verify the ASP.NET Core IIS module.

```powershell
Test-Path "$env:ProgramFiles\IIS\Asp.Net Core Module\V2\aspnetcorev2.dll"
```

Expected result:

```text
True
```

---

# 5. Configure IIS

## 5.1 Enable IIS Features

Open:

```
optionalfeatures
```

Enable the following features.

### Web Management Tools

- IIS Management Console

### Common HTTP Features

- Default Document
- HTTP Errors
- Static Content

### Health and Diagnostics

- HTTP Logging

### Performance Features

- Static Content Compression
- Dynamic Content Compression

### Security

- Request Filtering

### Application Development Features

- WebSocket Protocol

Do not enable legacy ASP.NET or ISAPI features.

---

## 5.2 Verify IIS

Browse to:

```
http://localhost
```

The IIS welcome page should be displayed.

Open **Internet Information Services (IIS) Manager** and verify the server is available.

---

# 6. Create Deployment Directories

Create the application directory.

```powershell
New-Item `
    -ItemType Directory `
    -Path "C:\inetpub\wwwroot\Soteria" `
    -Force
```

Create the Data Protection directory.

```powershell
New-Item `
    -ItemType Directory `
    -Path "C:\ProgramData\Soteria\DataProtection" `
    -Force
```

Create the database directory.

```powershell
New-Item `
    -ItemType Directory `
    -Path "C:\ProgramData\Soteria\Database" `
    -Force
```

---

## 6.1 Verification

Verify the directory structure.

```text
C:\
├── inetpub
│   └── wwwroot
│       └── Soteria
└── ProgramData
    └── Soteria
        ├── Database
        └── DataProtection
```

No application files should be published at this stage.

The remaining sections describe configuring IIS to host the application.

# 7. Configure the IIS Application Pool

## 7.1 Create the Application Pool

Open **Internet Information Services (IIS) Manager**.

Navigate to:

```
Application Pools
```

Select:

```
Add Application Pool...
```

Configure the new Application Pool.

| Setting | Value |
|---------|-------|
| Name | Soteria |
| .NET CLR Version | No Managed Code |
| Managed Pipeline Mode | Integrated |
| Start Application Pool Immediately | Enabled |

Select **OK**.

---

## 7.2 Configure Advanced Settings

Right-click the **Soteria** Application Pool.

Select:

```
Advanced Settings...
```

Configure the following settings.

### General

| Setting | Value |
|---------|-------|
| Start Mode | AlwaysRunning |

### Process Model

| Setting | Value |
|---------|-------|
| Identity | ApplicationPoolIdentity |
| Idle Time-out (minutes) | 0 |

### Recycling

| Setting | Value |
|---------|-------|
| Regular Time Interval (minutes) | 0 |

Leave all remaining settings at their default values.

---

## 7.3 Application Pool Identity

The Application Pool now runs under the virtual account:

```text
IIS AppPool\Soteria
```

This account will later require permission to:

- Read the published application.
- Read the OpenIddict certificate private keys.
- Modify the SQLite database directory.
- Modify the Data Protection directory.

No Windows user account needs to be created.

---

## 7.4 Verification

Verify that the Application Pool status is:

```
Started
```

The configured identity should be:

```
ApplicationPoolIdentity
```

---

## 7.5 Troubleshooting

### Incorrect CLR Version

If the Application Pool is configured for:

```
.NET CLR Version v4.0
```

change it to:

```
No Managed Code
```

ASP.NET Core applications do not execute inside the IIS CLR.

---

### Application Pool Stops Immediately

If the pool refuses to remain started:

- verify the .NET Hosting Bundle has been installed.
- verify the ASP.NET Core Module is installed.
- check the Windows Event Log.

Do not continue until the Application Pool remains running.

---

# 8. Create the IIS Website

## 8.1 Configure the Hosts File

Open an elevated PowerShell session.

Launch Notepad.

```powershell
notepad "$env:SystemRoot\System32\drivers\etc\hosts"
```

Add:

```text
127.0.0.1 soteria.local
```

Save the file.

Flush the DNS cache.

```powershell
ipconfig /flushdns
```

Verify name resolution.

```powershell
Resolve-DnsName soteria.local
```

Expected result:

```text
127.0.0.1
```

---

## 8.2 Create the Website

In IIS Manager select:

```
Sites
```

Select:

```
Add Website...
```

Configure the website.

| Setting | Value |
|---------|-------|
| Site Name | Soteria |
| Application Pool | Soteria |
| Physical Path | C:\inetpub\wwwroot\Soteria |

Configure the initial HTTP binding.

| Setting | Value |
|---------|-------|
| Type | HTTP |
| IP Address | 127.0.0.1 |
| Port | 80 |
| Host Name | soteria.local |

Select **Start Website Immediately**.

Select **OK**.

---

## 8.3 Verification

Verify:

- Website status is **Started**.
- Application Pool is **Soteria**.
- Physical Path is correct.
- Host Name is **soteria.local**.

---

# 9. Configure HTTPS

## 9.1 Create the HTTPS Certificate

Open an elevated PowerShell session.

Run:

```powershell
$httpsCertificate = New-SelfSignedCertificate `
    -Type SSLServerAuthentication `
    -Subject "CN=soteria.local" `
    -DnsName "soteria.local" `
    -FriendlyName "Soteria HTTPS" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy NonExportable `
    -NotBefore (Get-Date).AddMinutes(-5) `
    -NotAfter (Get-Date).AddYears(5)
```

Verify the certificate.

```powershell
$httpsCertificate |
Select Subject,FriendlyName,Thumbprint,HasPrivateKey
```

Expected:

```text
Subject         : CN=soteria.local
FriendlyName    : Soteria HTTPS
HasPrivateKey   : True
```

---

## 9.2 Trust the Certificate

Create a temporary directory.

```powershell
New-Item `
    -ItemType Directory `
    -Path "C:\Temp\Soteria" `
    -Force
```

Export the public certificate.

```powershell
Export-Certificate `
    -Cert $httpsCertificate `
    -FilePath "C:\Temp\Soteria\soteria.local.cer"
```

Import it into the Trusted Root store.

```powershell
Import-Certificate `
    -FilePath "C:\Temp\Soteria\soteria.local.cer" `
    -CertStoreLocation "Cert:\LocalMachine\Root"
```

---

## 9.3 Verify the Certificate

Open:

```
certlm.msc
```

Verify the certificate exists in:

```
Personal
    Certificates
```

and

```
Trusted Root Certification Authorities
    Certificates
```

The Personal certificate should contain a private key.

The Trusted Root certificate should not.

---

## 9.4 Configure the HTTPS Binding

Open:

```
IIS Manager
```

Select:

```
Sites
→ Soteria
→ Bindings...
→ Add...
```

Configure:

| Setting | Value |
|---------|-------|
| Type | HTTPS |
| IP Address | All Unassigned |
| Port | 443 |
| Host Name | soteria.local |
| SSL Certificate | Soteria HTTPS |
| Require Server Name Indication | Enabled |

Select **OK**.

---

## 9.5 Verification

Verify the IIS bindings.

```powershell
Import-Module WebAdministration

Get-WebBinding -Name "Soteria"
```

Expected:

```text
http   127.0.0.1:80:soteria.local
https  *:443:soteria.local
```

The HTTPS binding should have:

```
SslFlags = 1
```

indicating Server Name Indication (SNI).

---

## 9.6 Browser Verification

Browse to:

```
https://soteria.local
```

At this stage the application has not yet been deployed.

An IIS error such as:

```
HTTP Error 403.14 - Forbidden
```

is expected.

The important verification points are:

- HTTPS is used.
- The browser trusts the certificate.
- No certificate warning is displayed.
- The certificate subject is **soteria.local**.

---

## 9.7 Troubleshooting

### Browser reports an untrusted certificate

Verify the certificate exists in:

```
Trusted Root Certification Authorities
```

and not only:

```
Personal
```

---

### Binding Conflict

If IIS reports that another site already uses the binding:

Verify that no other site has:

```
https
*:443
soteria.local
```

Multiple HTTPS sites may share port **443** provided each uses a unique Host Name with **Server Name Indication (SNI)** enabled.

---

### Host Name Does Not Resolve

Verify the Hosts file contains:

```text
127.0.0.1 soteria.local
```

Run:

```powershell
ipconfig /flushdns
Resolve-DnsName soteria.local
```

Do not continue until the name resolves correctly.

# 10. Install the OpenIddict Certificates

## 10.1 Purpose

Soteria uses two X.509 certificates for OpenIddict.

| Certificate | Purpose |
|------------|---------|
| Soteria OpenIddict Signing | Signs access and refresh tokens |
| Soteria OpenIddict Encryption | Encrypts access and refresh tokens |

These certificates are separate from the HTTPS certificate and should never be reused for HTTPS.

---

## 10.2 Create the Signing Certificate

Open an elevated PowerShell session.

Run:

```powershell
$signingCertificate = New-SelfSignedCertificate `
    -Subject "CN=Soteria OpenIddict Signing" `
    -FriendlyName "Soteria OpenIddict Signing" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy NonExportable `
    -KeyUsage DigitalSignature `
    -NotBefore (Get-Date).AddMinutes(-5) `
    -NotAfter (Get-Date).AddYears(10)
```

---

## 10.3 Create the Encryption Certificate

Run:

```powershell
$encryptionCertificate = New-SelfSignedCertificate `
    -Subject "CN=Soteria OpenIddict Encryption" `
    -FriendlyName "Soteria OpenIddict Encryption" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy NonExportable `
    -KeyEncipherment `
    -NotBefore (Get-Date).AddMinutes(-5) `
    -NotAfter (Get-Date).AddYears(10)
```

---

## 10.4 Record the Thumbprints

Run:

```powershell
Get-ChildItem Cert:\LocalMachine\My |
Where-Object FriendlyName -like "Soteria*" |
Select FriendlyName,Thumbprint
```

Record the thumbprints.

These values will be used in the Production configuration.

---

## 10.5 Verification

Open:

```
certlm.msc
```

Verify both certificates exist in:

```
Personal
    Certificates
```

Each certificate should:

- have a private key
- be valid
- not be expired

---

# 11. Configure Certificate Permissions

## 11.1 Purpose

The IIS Application Pool identity must be able to access the private keys for both OpenIddict certificates.

Without these permissions Soteria will fail during startup.

---

## 11.2 Grant Private Key Permissions

Open:

```
certlm.msc
```

Navigate to:

```
Personal
    Certificates
```

For each OpenIddict certificate:

Right-click

```
All Tasks
→ Manage Private Keys...
```

Add:

```
IIS AppPool\Soteria
```

Grant:

```
Read
```

Repeat for:

- Soteria OpenIddict Signing
- Soteria OpenIddict Encryption

---

## 11.3 Verification

Restart the Application Pool.

No certificate permission errors should appear in the Windows Event Log.

---

## 11.4 Troubleshooting

### Startup Failure

If IIS reports:

```
HTTP Error 500.30
```

Check the Application Event Log.

Certificate permission failures commonly indicate that the Application Pool identity has not been granted access to the certificate private key.

---

# 12. Configure Data Protection

## 12.1 Purpose

ASP.NET Core Data Protection is responsible for:

- Authentication cookies
- Anti-forgery tokens
- Other encrypted application state

Production deployments must persist the Data Protection keys outside the application directory.

---

## 12.2 Directory

The deployment directory should be:

```text
C:\ProgramData\Soteria\DataProtection
```

If it does not already exist:

```powershell
New-Item `
    -ItemType Directory `
    -Path "C:\ProgramData\Soteria\DataProtection" `
    -Force
```

---

## 12.3 Grant Permissions

Grant the Application Pool Modify permission.

```powershell
icacls "C:\ProgramData\Soteria\DataProtection" `
    /grant "IIS AppPool\Soteria:(OI)(CI)M"
```

---

## 12.4 Verification

Verify the ACL.

```powershell
icacls "C:\ProgramData\Soteria\DataProtection"
```

Expected output should include:

```text
IIS AppPool\Soteria
    (OI)(CI)(M)
```

---

## 12.5 Expected Behaviour

Following the first successful startup the directory should contain XML key files similar to:

```text
key-xxxxxxxx.xml
```

These keys must survive:

- Application Pool recycling
- IIS restart
- Application redeployment

Deleting these files invalidates all authentication cookies.

---

# 13. Configure the SQLite Database

## 13.1 Purpose

The SQLite database is stored separately from the published application to ensure deployments do not overwrite application data.

---

## 13.2 Directory

The database directory is:

```text
C:\ProgramData\Soteria\Database
```

Create it if required.

```powershell
New-Item `
    -ItemType Directory `
    -Path "C:\ProgramData\Soteria\Database" `
    -Force
```

---

## 13.3 Grant Permissions

Grant Modify permission.

```powershell
icacls "C:\ProgramData\Soteria\Database" `
    /grant "IIS AppPool\Soteria:(OI)(CI)M"
```

---

## 13.4 Verification

Verify:

```powershell
icacls "C:\ProgramData\Soteria\Database"
```

The Application Pool identity should have Modify permission.

---

## 13.5 Expected Behaviour

On the first migration Soteria will create:

```text
C:\ProgramData\Soteria\Database\soteria.db
```

Subsequent deployments reuse this database.

The publish process should never overwrite this file.

---

# 14. Configure Production Settings

## 14.1 Configure the Production Configuration

Verify that the Production configuration references:

- the SQLite database location
- the Data Protection location
- the OpenIddict certificate thumbprints

The database connection should reference:

```text
C:\ProgramData\Soteria\Database\soteria.db
```

---

## 14.2 Environment Variables

Any required Production secrets should be configured using Windows Environment Variables.

At the time of writing, Soteria still requires:

```
OpenIddict__EncryptionKey
```

This requirement exists for backwards compatibility and is expected to be removed once the application relies solely on certificate-based encryption.

---

## 14.3 Verification

Restart IIS.

```powershell
iisreset
```

The application should start without configuration errors.

No OpenIddict configuration exceptions should appear in the Windows Event Log.

---

## 14.4 Troubleshooting

### HTTP Error 500.30

Enable stdout logging temporarily.

Inspect:

- stdout log
- Windows Event Log

During the initial deployment this error was traced to a missing:

```
OpenIddict__EncryptionKey
```

environment variable.

Once corrected the application started successfully.

# 15. Publish Soteria

## 15.1 Purpose

Publish the Soteria application into the IIS website directory.

The publish process updates only the application binaries.

Persistent application data remains outside the publish directory.

---

## 15.2 Build the Release Package

Open a terminal in the solution directory.

Run:

```powershell
dotnet publish `
    --configuration Release `
    --output ".\publish"
```

Verify the publish completes successfully.

---

## 15.3 Stop the Website (Recommended)

For the initial deployment this step is optional.

For future deployments it is recommended to place the application offline before replacing the published files.

Create an `app_offline.htm` file in the website root.

```powershell
New-Item `
    -ItemType File `
    -Path "C:\inetpub\wwwroot\Soteria\app_offline.htm" `
    -Force
```

IIS will gracefully unload the application.

---

## 15.4 Deploy the Published Files

Copy the contents of the publish folder into:

```text
C:\inetpub\wwwroot\Soteria
```

PowerShell example:

```powershell
Copy-Item `
    ".\publish\*" `
    "C:\inetpub\wwwroot\Soteria" `
    -Recurse `
    -Force
```

When deployment is complete remove:

```text
app_offline.htm
```

```powershell
Remove-Item `
    "C:\inetpub\wwwroot\Soteria\app_offline.htm"
```

The application will automatically restart.

---

## 15.5 Verification

Verify the website directory contains:

```text
Soteria.exe
web.config
wwwroot\
*.dll
```

No database or Data Protection files should exist in this directory.

---

# 16. Apply Entity Framework Core Migrations

## 16.1 Purpose

Create or update the Production database schema.

---

## 16.2 Apply Migrations

From the project directory run:

```powershell
dotnet ef database update `
    --configuration Release
```

The command should complete without errors.

---

## 16.3 Verification

Verify the database now exists.

```text
C:\ProgramData\Soteria\Database\soteria.db
```

Confirm the file timestamp reflects the migration.

---

## 16.4 Troubleshooting

### Database Cannot Be Created

Verify:

- The directory exists.
- The connection string references the correct location.
- `IIS AppPool\Soteria` has **Modify** permission.

---

# 17. First Production Startup

## 17.1 Start the Website

Open IIS Manager.

Start:

```
Application Pool
    Soteria
```

Verify the website is started.

If necessary restart IIS.

```powershell
iisreset
```

---

## 17.2 Browse to the Site

Open:

```text
https://soteria.local
```

The Soteria login page should be displayed.

---

## 17.3 Verify HTTPS

Confirm:

- HTTPS is used.
- The browser reports a secure connection.
- No certificate warnings are displayed.

---

## 17.4 Verify Authentication

Log into the application.

Confirm that authentication succeeds.

---

## 17.5 Verify Data Protection

Recycle the Application Pool.

```powershell
Restart-WebAppPool `
    -Name "Soteria"
```

Refresh the browser.

The authenticated session should still be active.

---

## 17.6 Verify IIS Restart

Restart IIS.

```powershell
iisreset
```

Return to:

```text
https://soteria.local
```

The authenticated session should still be valid.

This confirms that the Data Protection keys are being persisted correctly.

---

# 18. Redeployment Verification

## 18.1 Purpose

Verify that future deployments preserve operational state.

---

## 18.2 Create Sample Data

Within Soteria create representative data.

Examples include:

- Users
- Clients
- Applications
- Client Memberships

Record the created data.

---

## 18.3 Republish

Publish a new build.

Deploy using the procedure described in Section 15.

---

## 18.4 Verification

After deployment verify:

- The application starts successfully.
- Existing users can log in.
- Previously created data still exists.
- The SQLite database was not recreated.
- Authentication continues to function.

---

## 18.5 Expected Behaviour

Only the application binaries should change during deployment.

The following should remain unchanged:

```text
C:\ProgramData\Soteria\Database
```

and

```text
C:\ProgramData\Soteria\DataProtection
```

Successful completion confirms that application binaries are fully separated from persistent operational state.

---

# 19. Production Deployment Checklist

A deployment is considered successful when all of the following have been verified.

| Item | Status |
|------|--------|
| .NET Hosting Bundle installed | ☐ |
| IIS configured | ☐ |
| Application Pool created | ☐ |
| Website created | ☐ |
| HTTPS configured | ☐ |
| HTTPS certificate trusted | ☐ |
| OpenIddict Signing certificate installed | ☐ |
| OpenIddict Encryption certificate installed | ☐ |
| Certificate private key permissions configured | ☐ |
| Data Protection directory configured | ☐ |
| SQLite directory configured | ☐ |
| Application published | ☐ |
| Database migrated | ☐ |
| Application starts successfully | ☐ |
| Login succeeds | ☐ |
| Authentication survives Application Pool recycle | ☐ |
| Authentication survives IIS restart | ☐ |
| Database survives redeployment | ☐ |

Completion of this checklist indicates that the Production deployment has been successfully verified.

# 20. Troubleshooting

This section describes the most common deployment issues encountered during the initial Soteria Production deployment and their resolution.

---

## 20.1 HTTP Error 500.30

### Symptoms

The browser displays:

```text
HTTP Error 500.30
ASP.NET Core app failed to start
```

### Cause

The application failed during startup.

This error is generic and does not identify the underlying problem.

---

### Resolution

Temporarily enable stdout logging in `web.config`.

```xml
stdoutLogEnabled="true"
stdoutLogFile=".\logs\stdout"
```

Create the log directory.

```powershell
New-Item `
    -ItemType Directory `
    -Path "C:\inetpub\wwwroot\Soteria\logs" `
    -Force
```

Recycle the Application Pool.

Inspect the generated log file.

When troubleshooting is complete disable stdout logging again.

---

### Also Check

Open:

```
Event Viewer
→ Windows Logs
→ Application
```

Startup exceptions are usually recorded here.

---

## 20.2 Missing Hosting Bundle

### Symptoms

The Application Pool starts but every request returns:

```
HTTP Error 500.31
```

or

```
HTTP Error 500.30
```

---

### Resolution

Install or repair the latest .NET Hosting Bundle.

Restart IIS.

```powershell
iisreset
```

Verify:

```powershell
dotnet --list-runtimes
```

---

## 20.3 Missing OpenIddict Environment Variable

### Symptoms

Startup fails with:

```text
The OpenIddict:EncryptionKey configuration value is required.
```

---

### Cause

The Production environment variable has not been configured.

---

### Resolution

Create the required Windows Environment Variable.

```
OpenIddict__EncryptionKey
```

Restart IIS.

```powershell
iisreset
```

---

### Future Improvement

This requirement exists for backwards compatibility.

The long-term design is for Production deployments to rely entirely on the OpenIddict certificates without requiring an additional encryption key.

---

## 20.4 Certificate Permission Errors

### Symptoms

Application startup fails.

The Event Log contains certificate access exceptions.

---

### Resolution

Verify:

```
certlm.msc
```

For both OpenIddict certificates:

```
Manage Private Keys...
```

Ensure:

```
IIS AppPool\Soteria
```

has:

```
Read
```

permission.

---

## 20.5 Data Protection Issues

### Symptoms

Users are logged out after:

- Application Pool recycle
- IIS restart

---

### Cause

The Data Protection keys are not being persisted.

---

### Resolution

Verify:

```text
C:\ProgramData\Soteria\DataProtection
```

contains XML key files.

Verify:

```
IIS AppPool\Soteria
```

has Modify permission.

---

## 20.6 Database Cannot Be Created

### Symptoms

SQLite reports:

```
Unable to open database file
```

---

### Resolution

Verify:

```text
C:\ProgramData\Soteria\Database
```

exists.

Verify:

```
IIS AppPool\Soteria
```

has Modify permission.

Verify the Production connection string references:

```text
C:\ProgramData\Soteria\Database\soteria.db
```

---

## 20.7 Browser Certificate Warning

### Symptoms

The browser displays an HTTPS warning.

---

### Resolution

Verify the HTTPS certificate exists in:

```
Trusted Root Certification Authorities
```

Verify the certificate Subject is:

```
CN=soteria.local
```

Verify the Hosts file contains:

```text
127.0.0.1 soteria.local
```

---

# 21. Backup and Recovery

## 21.1 Purpose

The Soteria application binaries can always be recreated from source.

Operational state cannot.

Backup procedures should therefore focus on preserving application state rather than published files.

---

## 21.2 Files to Backup

### SQLite Database

```text
C:\ProgramData\Soteria\Database
```

---

### Data Protection Keys

```text
C:\ProgramData\Soteria\DataProtection
```

---

### Production Configuration

Any Production configuration files and Windows Environment Variables.

---

### OpenIddict Certificates

Export and securely store:

- Soteria OpenIddict Signing
- Soteria OpenIddict Encryption

If using self-signed HTTPS certificates, also export:

- Soteria HTTPS

Private keys should be password protected.

---

## 21.3 Files That Do Not Require Backup

The following can always be recreated:

```text
C:\inetpub\wwwroot\Soteria
```

These files are deployment artefacts and should be reproduced by publishing a Release build.

---

## 21.4 Recovery Procedure

To recover a Production server:

1. Install Windows.
2. Install IIS.
3. Install the .NET Hosting Bundle.
4. Restore the OpenIddict certificates.
5. Restore the HTTPS certificate.
6. Restore the SQLite database.
7. Restore the Data Protection keys.
8. Restore the Production configuration.
9. Publish the application.
10. Start IIS.
11. Verify successful login.

Provided the database, certificates and Data Protection keys are restored together, users should remain authenticated and application data should be preserved.

---

# 22. Conclusion

A successful deployment should result in:

- IIS hosting the Soteria application.
- HTTPS secured by the Soteria HTTPS certificate.
- OpenIddict using dedicated signing and encryption certificates.
- Data Protection keys persisted outside the application directory.
- SQLite persisted outside the application directory.
- Application redeployments updating only the application binaries.
- User authentication surviving Application Pool recycling and IIS restarts.

This deployment architecture provides a clear separation between application binaries and operational state, enabling safe redeployment, simplified backup procedures and predictable recovery.

