## Phase 7 — Soteria Deployment and Operations

### Milestone 7.1 — Establish the Deployment Baseline

#### Task 7.1.1 — Confirm the Soteria deployment scope

Deliverables:

* Confirm that Phase 7 applies only to the Soteria application.
* Exclude ReferenceWeb and ReferenceApi from the initial deployment scope.
* Confirm Windows 11 Pro as the target host operating system.
* Confirm IIS as the hosting platform.
* Confirm that the application will initially be accessible only from the local machine.
* Confirm `https://soteria.local` as the canonical application URL and OpenIddict issuer.
* Record any known limitations of the initial local-only deployment.

#### Task 7.1.2 — Establish that no hidden configuration exists

Deliverables:

* Review the Soteria project for configuration sources outside the known `appsettings` and environment-variable configuration.
* Review project-owned startup extensions and service-registration methods for implicit configuration dependencies.
* Review launch profiles, publish profiles, scripts, and source-controlled IIS configuration.
* Review file-system paths used by the application.
* Review configuration values read directly through `IConfiguration`.
* Produce a complete configuration inventory.
* Identify which configuration values are development-only.
* Identify which configuration values are required in the deployed environment.
* Record any unresolved configuration dependencies before deployment implementation begins.

#### Task 7.1.3 — Establish the current production-readiness gaps

Deliverables:

* Review the application startup path when `ASPNETCORE_ENVIRONMENT` is not `Development`.
* Establish how OpenIddict signing credentials are currently registered.
* Establish how OpenIddict encryption credentials are currently registered.
* Establish whether ASP.NET Core Data Protection keys are persisted.
* Establish how Identity emails are handled outside development.
* Establish whether startup initializers are safe and appropriate for every deployed startup.
* Establish whether the application currently depends on development certificates, localhost URLs, or development-only services.
* Produce a documented list of changes required before the application can run under IIS.

---

### Milestone 7.2 — Define the Deployment Architecture

#### Task 7.2.1 — Define the IIS hosting model

Deliverables:

* Define the IIS site name.
* Define the application pool name.
* Define whether the application pool uses `ApplicationPoolIdentity` or a dedicated Windows account.
* Define the application pool runtime and managed pipeline settings.
* Define the physical deployment directory.
* Define the process model and application restart behaviour.
* Define whether IIS hosts Soteria as a dedicated site or beneath an existing site.
* Define the permissions required by the IIS worker process.

#### Task 7.2.2 — Define the deployment directory structure

Deliverables:

* Define the application binary directory.
* Define the persistent data directory.
* Define the SQLite database location.
* Define the Data Protection key directory.
* Define the certificate or key-material location, where file-based credentials are used.
* Define the log directory, where file logging is introduced.
* Separate replaceable application files from persistent operational data.
* Define directory ownership and access permissions.
* Ensure application publication does not overwrite persistent data.

#### Task 7.2.3 — Define hostname and HTTPS handling

Deliverables:

* Define the local hosts-file entry for `soteria.local`.
* Define the IIS HTTPS binding.
* Define how the HTTPS certificate will be created or obtained.
* Define where the certificate will be installed.
* Define which Windows certificate store will contain it.
* Define certificate private-key permissions for the IIS application pool.
* Define how the certificate will be trusted on the local machine.
* Confirm that the application issuer is exactly `https://soteria.local`.
* Define how certificate expiry and replacement will be handled.

---

### Milestone 7.3 — Define Production Configuration and Secret Management

#### Task 7.3.1 — Define the production configuration model

Deliverables:

* Decide whether deployed configuration will use `appsettings.Production.json`, Windows environment variables, a `.env` file, or a documented combination.
* Define which configuration values may remain in source-controlled JSON files.
* Define which values must be supplied outside source control.
* Define configuration precedence for the deployed application.
* Define the production connection string.
* Define the production OpenIddict token lifetime settings.
* Define the bootstrap administrator configuration.
* Define logging levels for production.
* Define the deployed `AllowedHosts` value.
* Produce a complete production configuration template containing no secrets.

#### Task 7.3.2 — Define secret storage

Deliverables:

* Inventory all secrets required by Soteria.
* Distinguish application secrets from cryptographic certificates and keys.
* Decide whether secrets will be stored as machine-level or process-level Windows environment variables.
* Decide whether a `.env` file is acceptable for the local deployment.
* Define file permissions if `.env` is retained.
* Define how secrets are introduced during initial deployment.
* Define how secrets are changed without modifying source-controlled files.
* Define how secret values are excluded from logs and documentation.
* Define a secret-rotation procedure.

---

### Milestone 7.4 — Establish the Database Deployment Model

#### Task 7.4.1 — Establish the database state for first deployment

Deliverables:

* Decide whether the first deployment will use the existing development database or a new database.
* If the existing database is retained, verify that its data is suitable for the deployed environment.
* If a new database is used, define how it will be created from migrations.
* Establish whether the bootstrap administrator should already exist before deployment.
* Establish how the initial Soteria Administrator will be assigned.
* Establish whether the existing reference client and scope records should exist in the deployed database.
* Establish whether development or test records must be removed.
* Define the expected database state immediately after first startup.
* Produce a first-deployment database checklist.

#### Task 7.4.2 — Define the persistent SQLite location and access model

Deliverables:

* Move the deployed SQLite database outside the replaceable application publication directory, if required by the chosen layout.
* Define an absolute or deployment-safe connection string.
* Define IIS application-pool permissions for the database file and containing directory.
* Confirm that SQLite can create journal, shared-memory, and temporary files in the selected directory.
* Define whether `Cache=Shared` remains appropriate.
* Define how accidental concurrent application instances will be prevented.
* Define how database-file integrity will be checked.

#### Task 7.4.3 — Define the migration procedure

Deliverables:

* Confirm that migrations will be applied manually.
* Define the command used to apply migrations.
* Define where the migration command is executed.
* Define which environment and configuration values are supplied to the migration process.
* Require an application stop before migration where appropriate.
* Require a successful database backup before migration.
* Define how migration success is verified.
* Define how migration failure is handled.
* Define when the application may be restarted.
* Produce a repeatable migration runbook.

#### Task 7.4.4 — Define database backup and rollback

Deliverables:

* Define the backup location.
* Define the database backup naming convention.
* Define whether associated SQLite journal files require handling.
* Define the application-stop requirement before file-copy backup.
* Define how backup completion is verified.
* Define backup retention expectations.
* Define the rollback procedure following a failed migration or deployment.
* Define how a restored database is verified before application restart.
* Perform and document a test backup and restore.

---

### Milestone 7.5 — Implement Production Credential Management

#### Task 7.5.1 — Implement OpenIddict signing credentials

Deliverables:

* Select the production signing-certificate model.
* Create or obtain the signing certificate.
* Define its subject, validity period, key usage, and storage location.
* Install the certificate in the selected Windows certificate store.
* Grant the IIS application-pool identity access to its private key.
* Add production configuration for identifying the certificate.
* Replace development-only signing-certificate registration in the deployed environment.
* Fail application startup with a clear error when the configured certificate cannot be loaded.
* Verify that issued tokens are signed using the production credential.
* Document signing-certificate renewal and rotation.

#### Task 7.5.2 — Implement OpenIddict encryption credentials

Deliverables:

* Select the production token-encryption model.
* Decide whether token encryption uses a certificate or another supported persistent key.
* Create and protect the encryption credential.
* Register the credential outside the Development-only startup branch.
* Ensure the credential remains stable across application restarts and redeployments.
* Fail startup clearly when the credential is unavailable.
* Verify that authorization codes, refresh tokens, and other encrypted artifacts remain usable across an application restart.
* Document encryption-key rotation and its effect on existing tokens.

#### Task 7.5.3 — Implement persistent Data Protection

Deliverables:

* Define the Data Protection application name.
* Configure persistent Data Protection key storage.
* Grant the IIS application-pool identity access to the key directory.
* Decide whether keys require additional protection at rest.
* Ensure keys survive application publication and restart.
* Verify that authentication cookies remain valid across an application restart.
* Verify that Identity tokens remain usable for their intended lifetime.
* Document Data Protection backup and recovery requirements.

---

### Milestone 7.6 — Make Soteria Production-Ready

#### Task 7.6.1 — Resolve deployed email behaviour

Deliverables:

* Establish which account workflows require email delivery.
* Decide whether deployed email functionality will use a real email provider, an operational substitute, or be explicitly unavailable.
* Prevent confirmation links, password-reset links, and reset codes from being written to production logs.
* Ensure unavailable email functionality fails safely and clearly.
* Define the configuration required by the selected email implementation.
* Verify registration, confirmation, forgotten-password, and password-reset behaviour in the deployed environment.
* Document any intentionally unsupported email workflows.

#### Task 7.6.2 — Review startup initializers

Deliverables:

* Confirm the intended deployed behaviour of `OpenIddictInitializer`.
* Decide whether reference client and scope initialization remains part of Soteria startup.
* Confirm whether initializer updates are idempotent and safe on every startup.
* Confirm the intended deployed behaviour of `SoteriaAdministratorInitializer`.
* Verify bootstrap behaviour against the selected first-deployment database state.
* Ensure initializer failures stop startup with actionable errors.
* Ensure initializers do not silently overwrite operational configuration.
* Document all automatic startup changes to persistent data.

#### Task 7.6.3 — Configure production logging

Deliverables:

* Define the production logging providers.
* Define minimum log levels.
* Reduce unnecessary framework logging.
* Ensure secrets, passwords, tokens, reset links, confirmation links, and certificate private information are never logged.
* Decide whether logs are written to Windows Event Log, files, or another local target.
* Define log-file location and permissions where applicable.
* Define log retention.
* Confirm that IIS startup failures can be diagnosed.
* Define the logs required for authentication and token-flow troubleshooting.

#### Task 7.6.4 — Implement production startup validation

Deliverables:

* Validate the production connection string at startup.
* Validate required directories and write permissions.
* Validate signing credentials.
* Validate encryption credentials.
* Validate Data Protection configuration.
* Validate required bootstrap configuration.
* Validate the canonical issuer configuration.
* Produce clear startup errors for missing or invalid deployment configuration.
* Ensure development-only fallbacks cannot be used silently in production.

---

### Milestone 7.7 — Build the Soteria Deployment Package

#### Task 7.7.1 — Define the publication process

Deliverables:

* Define the target .NET runtime model.
* Decide between framework-dependent and self-contained publication.
* Define the publish command.
* Define the release configuration.
* Define the output directory.
* Confirm that the ASP.NET Core Hosting Bundle requirements are documented.
* Exclude development-only files and secrets from the package.
* Ensure persistent application data is not included accidentally.
* Verify the generated IIS `web.config`.
* Produce a repeatable publication procedure.

#### Task 7.7.2 — Establish deployment package contents

Deliverables:

* Inventory the files required for a successful deployment.
* Inventory the files that must not be deployed.
* Include the production configuration template.
* Include migration tooling or documented migration commands.
* Include certificate and secret prerequisites without embedding secrets.
* Include the deployment verification checklist.
* Confirm that the package can be deployed to a clean target directory.
* Record the application version or source revision represented by each package.

---

### Milestone 7.8 — Deploy Soteria to IIS

#### Task 7.8.1 — Prepare the Windows host

Deliverables:

* Enable the required IIS features.
* Install the compatible ASP.NET Core Hosting Bundle.
* Confirm the required .NET runtime is installed.
* Create the deployment directories.
* Create the persistent data and key directories.
* Configure directory permissions.
* Install and trust the HTTPS certificate.
* Add the `soteria.local` hosts-file entry.
* Confirm that port 443 is available.

#### Task 7.8.2 — Configure the IIS application

Deliverables:

* Create the Soteria application pool.
* Configure the application-pool identity.
* Configure the application-pool runtime settings.
* Create the IIS site.
* Configure the physical path.
* Configure the HTTPS binding for `soteria.local`.
* Associate the correct certificate.
* Configure production environment variables.
* Configure application startup and shutdown behaviour.
* Verify that the worker process can access the application, database, keys, and certificates.

#### Task 7.8.3 — Perform the initial database deployment

Deliverables:

* Stop the IIS application.
* Create the pre-deployment database backup where an existing database is used.
* Create or place the deployment database in the persistent data directory.
* Apply the current migrations manually.
* Verify the schema version.
* Verify required seeded data.
* Verify the expected administrator-bootstrap state.
* Verify directory and database permissions.
* Record the completed database deployment.

#### Task 7.8.4 — Perform the initial application deployment

Deliverables:

* Publish the release build.
* Copy the deployment package to the IIS application directory.
* Apply the production configuration.
* Install or reference the required credentials.
* Start the IIS application.
* Confirm successful application startup.
* Confirm that no development-only certificate or service is being used.
* Confirm that the application is reachable at `https://soteria.local`.
* Record the deployed application version.

---

### Milestone 7.9 — Verify the Deployed Soteria Application

#### Task 7.9.1 — Verify platform and application startup

Deliverables:

* Verify HTTPS certificate trust.
* Verify hostname resolution.
* Verify the issuer metadata is available from `https://soteria.local`.
* Verify the issuer reported by OpenIddict matches the canonical URL.
* Verify the database opens successfully.
* Verify migrations are current.
* Verify persistent directories are writable only by intended identities.
* Verify application restart succeeds without data or key loss.
* Review startup logs for errors and warnings.

#### Task 7.9.2 — Verify Identity functionality

Deliverables:

* Verify the expected registration availability.
* Verify initial administrator bootstrap where applicable.
* Verify login.
* Verify logout.
* Verify password change.
* Verify password reset according to the selected deployed email model.
* Verify account lockout behaviour.
* Verify administrator access restrictions.
* Verify a non-administrator cannot access protected administration functions.
* Verify authentication cookies survive an application restart where expected.

#### Task 7.9.3 — Verify OpenIddict functionality

Deliverables:

* Verify discovery metadata.
* Verify authorization endpoint availability.
* Verify token endpoint availability.
* Verify end-session endpoint availability.
* Verify issued tokens contain the expected issuer.
* Verify token signatures can be validated from published metadata.
* Verify encrypted token flows survive an application restart.
* Verify disabled clients are rejected.
* Verify client-membership enforcement remains operational.
* Verify token redemption and refresh behaviour against the configured lifetimes.

#### Task 7.9.4 — Verify operational safety

Deliverables:

* Verify secrets are absent from deployed files that should not contain them.
* Verify secrets and Identity action links are absent from production logs.
* Verify the database can be backed up.
* Verify the database can be restored.
* Verify Data Protection keys survive redeployment.
* Verify signing and encryption credentials survive redeployment.
* Verify the application fails clearly when required configuration or credentials are removed.
* Record all known deployment limitations and deferred improvements.

---

### Milestone 7.10 — Establish Routine Deployment and Operations

#### Task 7.10.1 — Define the routine deployment procedure

Deliverables:

* Define pre-deployment checks.
* Define application shutdown.
* Define database backup.
* Define migration execution.
* Define application-file replacement.
* Define configuration preservation.
* Define application restart.
* Define post-deployment verification.
* Define rollback criteria.
* Define rollback execution.
* Produce a concise repeatable deployment runbook.

#### Task 7.10.2 — Define routine operational checks

Deliverables:

* Define how application health is checked.
* Define how logs are reviewed.
* Define how database growth is monitored.
* Define how backup success is checked.
* Define how certificate expiry is monitored.
* Define how Data Protection key storage is checked.
* Define how disk usage is monitored.
* Define how failed authentication and token operations are investigated.
* Define the expected frequency of each operational check.

#### Task 7.10.3 — Define recovery procedures

Deliverables:

* Define recovery from a failed application deployment.
* Define recovery from a failed migration.
* Define recovery from database corruption.
* Define recovery from lost Data Protection keys.
* Define recovery from an expired or replaced HTTPS certificate.
* Define recovery from unavailable OpenIddict signing or encryption credentials.
* Define recovery from invalid production configuration.
* Define the evidence required before returning the application to service.
* Test the principal recovery procedures and record the results.

#### Task 7.10.4 — Complete the Soteria deployment documentation

Deliverables:

* Create `deployment.md` as the operational source of truth.
* Document the final architecture and directory structure.
* Document all required configuration.
* Document secret and certificate management.
* Document first deployment.
* Document routine deployment.
* Document migration, backup, restore, and rollback.
* Document verification procedures.
* Document operational monitoring and recovery.
* Record all known limitations and future deployment work.
* Update `current-state.md` with the completed deployment capability.
* Mark Phase 7 complete in `delivery-plan.md`.
