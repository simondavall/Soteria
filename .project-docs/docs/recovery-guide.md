# Soteria Recovery Guide

## 1. Purpose

This guide defines the verified recovery procedures for a deployed Soteria
Production instance following a failed deployment or the loss of critical
application data or credentials.

It provides concise recovery procedures for restoring the application,
Production database and deployment credentials.

This document provides only the recovery procedures. Detailed deployment
architecture, configuration requirements and implementation guidance are
documented separately in the Soteria Deployment Guide and Deployment Reference.

## 2. Application Recovery

Perform an application recovery if a deployment cannot be successfully completed
or the deployed application cannot be returned to a working state through normal
operational procedures.

1. Stop the **Soteria** IIS Application Pool.

2. Restore the previous application files to:

   ```text
   C:\inetpub\wwwroot\Soteria
   ```

3. If Entity Framework Core migrations were applied, restore the SQLite
   database backup created immediately before deployment.

4. Start the **Soteria** IIS Application Pool.

5. Complete the post-recovery verification procedure.

### Notes

- Restore the SQLite database only if the deployment modified the database
  schema or data.
- If the deployment failed before migrations were applied, restoring the
  previous application files is normally sufficient.

## 3. Database Recovery

Perform a database recovery if the Production SQLite database has become
corrupted, lost or requires restoration from a known backup.

1. Stop the **Soteria** IIS Application Pool.

2. Replace the Production database:

   ```text
   C:\ProgramData\Soteria\Database\soteria.db
   ```

   with the required backup.

3. Start the **Soteria** IIS Application Pool.

4. Complete the post-recovery verification procedure.

### Notes

- Restoring the SQLite database does not affect the published application,
  OpenIddict certificates, Data Protection key ring or Production
  configuration.
- The restored database should correspond to the deployed application version.

## 4. Credential Recovery

Perform credential recovery if the OpenIddict certificates or ASP.NET Core Data
Protection key ring are lost, replaced or require restoration.

### OpenIddict Certificates

1. Install the replacement certificate into the Windows
   `LocalMachine\My` certificate store.

2. Grant the **Soteria** IIS Application Pool Read access to the
   certificate private key.

3. Update the configured certificate thumbprint if required.

4. Restart the **Soteria** IIS Application Pool.

5. Complete the post-recovery verification procedure.

> Existing tokens signed or encrypted with the previous certificate may no
> longer be valid.

### Data Protection Key Ring

If a backup of the Data Protection key ring is available:

1. Stop the **Soteria** IIS Application Pool.

2. Restore the key files to:

   ```text
   C:\ProgramData\Soteria\DataProtection
   ```

3. Start the **Soteria** IIS Application Pool.

4. Complete the post-recovery verification procedure.

If no backup is available:

- Existing authentication cookies become invalid.
- Existing anti-forgery tokens become invalid.
- Users must authenticate again.
