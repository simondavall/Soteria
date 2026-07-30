This document provides a snapshot of the current implementation state of the project. 
It records completed work, the feature currently being developed, and the next expected 
steps. It should be updated regularly and is intended to help developers quickly understand 
where development should continue.

# Current phase

## Phase 6 – Application polish

# Current milestone

## Milestone 6.1 – Deployment Baseline

# Current task

- Establish production-readiness gaps.
  - Review startup behaviour outside Development.
  - Review credential management.
  - Review Data Protection.
  - Review startup initialisers.
  - Produce a list of deployment work required.

# Remaining milestone tasks

- None

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