This document provides a snapshot of the current implementation state of the project. 
It records completed work, the feature currently being developed, and the next expected 
steps. It should be updated regularly and is intended to help developers quickly understand 
where development should continue.

# Current phase

- Enhancements

# Current milestone

- None

# Current task

- Activate Required Password Change

# Remaining milestone tasks

- Refactor Soteria Program.cs

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
