# Soteria Deployment Runbook

## 1. Purpose

This document defines the operational procedure for upgrading and, if necessary,
rolling back a deployed Soteria Production instance.

It is intended to be used as a concise deployment checklist by an operator who
is already familiar with the Soteria deployment architecture.

This runbook deliberately omits detailed deployment guidance, configuration
information and architectural explanations, which are documented separately in
the Soteria Deployment Guide and Deployment Reference.

The procedures in this document assume the current verified Production
deployment architecture:

- Windows 11 Pro
- IIS
- SQLite
- HTTPS (`https://soteria.local`)

## 1. Purpose

This runbook defines the verified operational procedures for upgrading and, if
necessary, rolling back a deployed Soteria Production instance.

It is intended to be used during routine application deployments and assumes the
deployment environment has already been prepared and configured.

This document provides only the operational deployment sequence. Detailed
deployment architecture, configuration requirements and implementation guidance
are documented separately in the Soteria Deployment Guide and Deployment
Reference.

## 2. Upgrade Deployment

1. Confirm the deployment package has been published successfully.

2. Stop the **Soteria** IIS Application Pool.

3. Create a backup of the Production SQLite database.

4. Deploy the published application to:

   ```text
   C:\inetpub\wwwroot\Soteria
   ```

5. Apply the Entity Framework Core migrations from the solution root:

   ```bash
   $env:ConnectionStrings__SoteriaDb = "Data Source=C:\inetpub\data\Soteria\Soteria.db"

   dotnet ef database update --project .\Soteria --configuration Release
   ```
    The process-scoped connection string is required because dotnet ef does not inherit the environment variables configured for the IIS Application Pool.
6. Start the **Soteria** IIS Application Pool.

7. Complete the post-deployment verification checklist.

### Notes

The following Production resources must be preserved during deployment:

- SQLite database
- Data Protection key ring
- OpenIddict signing certificate
- OpenIddict encryption certificate
- HTTPS certificate
- Production configuration
- Application log files

## 3. Rollback Procedure

Perform a rollback only if the deployment cannot be successfully completed or
the post-deployment verification fails.

1. Stop the **Soteria** IIS Application Pool.

2. Restore the previous application files to:

   ```text
   C:\inetpub\wwwroot\Soteria
   ```

3. If Entity Framework Core migrations were applied, restore the SQLite
   database backup created immediately before deployment.

4. Start the **Soteria** IIS Application Pool.

5. Complete the post-deployment verification checklist.

### Notes

- Restore the SQLite database only if the deployment modified the database
  schema or data.
- If the deployment failed before migrations were applied, restoring the
  previous application files is normally sufficient.
## 4. Post-Deployment Verification

Verify the following before considering the deployment complete.

### Application

- [ ] The application starts successfully.
- [ ] No startup validation errors are reported.
- [ ] Production log files are created.

### Authentication

- [ ] A user can successfully authenticate.
- [ ] Existing user accounts remain accessible.
- [ ] Existing application data is present.

### OpenID Connect

- [ ] The discovery document is available.
- [ ] User authentication completes successfully.
- [ ] Access tokens are issued successfully.
- [ ] Protected API calls succeed.
- [ ] Automatic access-token renewal succeeds.

### Email

- [ ] Account confirmation emails can be sent.
- [ ] Password reset emails can be sent.

### Persistence

- [ ] Authentication survives an IIS Application Pool recycle.
- [ ] The SQLite database has been preserved.
- [ ] The Data Protection key ring has been preserved.

If all verification checks pass, the deployment is considered successful.
