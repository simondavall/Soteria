This document provides a snapshot of the current implementation state of the project. 
It records completed work, the feature currently being developed, and the next expected 
steps. It should be updated regularly and is intended to help developers quickly understand 
where development should continue.

# Current phase

- Enhancements

# Current milestone

- None

# Current task

- Refactor Soteria Program.cs

# Remaining milestone tasks

- Relocate log files to c:\inetpub\logs\Soteria
- Relocate data file to c:\inetpub\data\Soteria
- Add 'latest version' field to projects table

# Completed

- Replaced Windows DPAPI Data Protection key protection with cross-platform X.509 certificate protection.
- Retained filesystem-backed persistent Data Protection keys and the stable `Soteria` application name.
- Moved Production Data Protection key storage to `C:\inetpub\keys\Soteria`.
- Stored the Production Data Protection certificate under `C:\inetpub\certificates\Soteria`.
- Made the Data Protection key path, certificate path and certificate password host-configurable through environment variables.
- Restricted the IIS application-pool identity to the required key and certificate filesystem permissions.
- Verified persisted Data Protection keys are encrypted at rest.
- Verified authentication cookies remain valid across IIS application-pool recycling and application restart.
- Preserved existing Development Data Protection behaviour.
- Activated required password change for administrator-created users.
- Marked newly created users as requiring a password change before normal application access.
- Redirected authenticated users requiring a password change to the Change Password workflow.
- Enforced required password change across authenticated application navigation so the requirement cannot be bypassed by direct navigation.
- Preserved the user's intended destination through the required password-change workflow.
- Prevented the current password from being reused as the replacement password.
- Cleared `RequiresPasswordChange` only after a successful password change and persisted the completed state.
- Refreshed the authenticated session after the required password change and returned the user to their intended destination.
- Preserved the existing voluntary password-change behaviour for users who do not require a password change.
