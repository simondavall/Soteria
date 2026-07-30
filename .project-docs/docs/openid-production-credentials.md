Task 1 – Production Certificate Infrastructure

This establishes the foundation without changing application behaviour.

Deliverables

Create OpenIddictCertificateOptions.
Create OpenIddictServerBuilderExtensions.
Implement certificate lookup from LocalMachine\My.
Implement thumbprint normalisation.
Implement certificate loading helpers.
Add appsettings.Production.json with the certificate configuration structure.
Refactor Program.cs to use the new extension.

Outcome

The project has a clean production credential infrastructure, but still only supports Development credentials.
Task 2 – Environment Credential Registration

This introduces the production/development split.

Deliverables

Separate Development and non-Development credential registration.
Move development encryption-key lookup into the Development branch.
Register development credentials exactly as today.
Register production signing certificate.
Register production encryption certificate.
Remove any possibility of development credentials outside Development.

Outcome

Development behaves exactly as today.
Production now loads certificates correctly.
Task 3 – Production Validation & Fail-Fast Startup

This hardens the implementation.

Deliverables

Validate certificate configuration.
Validate thumbprints.
Validate certificate existence.
Validate private-key availability.
Validate certificate validity dates.
Validate RSA capability.
Ensure signing and encryption certificates are different.
Produce clear startup exception messages.

Outcome

Incorrect production deployments fail immediately with actionable errors.
Task 4 – Deployment Documentation & Verification

This completes the milestone.

Deliverables

Document IIS certificate installation.
Document private-key permissions.
Document required production configuration.
Produce a deployment verification checklist.
Verify Development behaviour.
Verify Production startup.
Verify token signing.
Verify token encryption.

Outcome

The implementation is production-ready and fully documented.