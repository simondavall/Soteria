This document provides a snapshot of the current implementation state of the project. 
It records completed work, the feature currently being developed, and the next expected 
steps. It should be updated regularly and is intended to help developers quickly understand 
where development should continue.

# Current phase

## Phase 6 – Deployment

# Current milestone

## Milestone 6.3 – Production Services

# Current task

- Configure production logging.
  - Define logging providers.
  - Configure production log levels.
  - Prevent secret disclosure.
  - Define log retention.
  - Verify production logging.

# Remaining milestone tasks

- Review startup initialisation.

# Completed

- Created the initial deployment documentation.
- Defined the purpose and scope of the deployment architecture.
- Confirmed Windows 11 Pro and IIS as the initial deployment platform.
- Confirmed SQLite as the initial deployment database.
- Confirmed the canonical deployment URL as https://soteria.local.
- Defined the initial single-machine deployment architecture.
- Recorded the initial deployment assumptions and constraints.
- Excluded the Reference Web Application and Reference API from the deployment scope.
- Reviewed all application configuration sources.
- Confirmed the application does not use ASP.NET Core User Secrets.
- Identified all deployment configuration sources.
- Produced the initial deployment configuration inventory.
- Confirmed no hidden application configuration exists outside the documented configuration sources.
- Identified development-only configuration dependencies.
- Reviewed production startup behaviour outside the Development environment.
- Identified production credential requirements.
- Identified ASP.NET Core Data Protection as a deployment requirement.
- Reviewed startup initialisation behaviour.
- Produced the production-readiness action list.
- Restructured the Phase 6 delivery plan to reflect the agreed deployment implementation sequence.
- Defined the production signing certificate strategy.
- Defined the production encryption certificate strategy.
- Implemented environment-specific OpenIddict credential registration.
- Preserved Development signing and encryption behaviour.
- Prevented development credentials from being registered outside the Development environment.
- Implemented production signing certificate registration.
- Implemented production encryption certificate registration.
- Implemented comprehensive production startup validation.
- Validated certificate configuration values.
- Validated certificate thumbprints and certificate existence.
- Validated private-key availability.
- Validated certificate validity periods.
- Validated RSA certificate capability.
- Prevented signing and encryption certificates from referencing the same certificate.
- Produced clear deployment-focused startup diagnostics for certificate failures.
- Verified Development credential registration.
- Verified Production startup using production certificates.
- Verified production token signing.
- Verified production token encryption.
- Produced the OpenIddict Production Certificate Deployment guide.
- Documented certificate installation and IIS private-key configuration.
- Documented production configuration requirements.
- Produced the production deployment verification checklist.
- Implemented persistent ASP.NET Core Data Protection for Production deployments.
- Configured a persistent Data Protection key ring outside the application directory.
- Protected Production Data Protection keys using Windows DPAPI (Local Machine).
- Standardised the Production Data Protection application name as `Soteria`.
- Verified authentication cookies survive IIS Application Pool recycling.
- Verified authentication cookies survive IIS restart.
- Verified Data Protection keys persist independently of application deployment.
- Implemented deployment directory validation during Production startup.
- Defined the canonical Production deployment directory structure.
- Standardised the published application location as `C:\inetpub\wwwroot\Soteria`.
- Standardised the SQLite database location as `C:\ProgramData\Soteria\Database`.
- Standardised the Data Protection key location as `C:\ProgramData\Soteria\DataProtection`.
- Defined the IIS Production hosting model.
- Defined the Production IIS Application Pool configuration.
- Defined Production HTTPS hosting using Server Name Indication (SNI).
- Verified HTTPS deployment using the `soteria.local` host name.
- Verified Production OpenIddict signing and encryption certificates under IIS.
- Verified IIS Application Pool access to OpenIddict certificate private keys.
- Verified Production startup under IIS.
- Verified Production SQLite deployment outside the published application directory.
  Verified database survives redeployment
- Produced the complete Production deployment architecture.
- Produced the Production deployment runbook.
- Produced the Production operations guide.
- Documented Production deployment verification procedures.
- Documented Production troubleshooting procedures.
- Documented Production backup and recovery procedures.
- Restricted local `.env` loading to the Development environment.
- Preserved the root `.env` file as the portable Development secret source.
- Ensured existing process environment variables take precedence over `.env` values.
- Removed the Production requirement for the symmetric OpenIddict encryption key.
- Preserved Development validation of the symmetric OpenIddict encryption key.
- Added clear Development startup diagnostics for missing, malformed and undersized encryption keys.
- Restricted Reference API scope initialisation to Development.
- Restricted Reference Web client initialisation to Development.
- Removed the Production dependency on the Reference Web OpenID Connect client secret.
- Confirmed the Production deployment requires no application-specific environment variables.
- Preserved optional first-user Soteria Administrator bootstrap in Production.
- Excluded the optional bootstrap administrator email from Production startup validation.
- Verified Production startup without Development-only secrets.
- Verified a refresh deployment succeeds with the revised environment-specific configuration.
- Completed environment-specific startup validation.
- Implemented production SMTP email delivery using a shared email sender.
- Replaced the Development logging email sender as the default Identity email provider.
- Added strongly typed SMTP configuration.
- Loaded SMTP configuration from `.env` during Development.
- Loaded SMTP configuration from environment variables in Production.
- Kept SMTP host, mailbox details and credentials outside committed configuration.
- Implemented startup validation for SMTP configuration.
- Preserved startup independence from SMTP server availability.
- Implemented HTML account confirmation emails.
- Implemented HTML password reset emails.
- Implemented password reset code email delivery.
- Verified account confirmation email delivery.
- Verified password reset email delivery.
- Verified standard ASP.NET Core Identity email workflows.