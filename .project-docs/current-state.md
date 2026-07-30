This document provides a snapshot of the current implementation state of the project. 
It records completed work, the feature currently being developed, and the next expected 
steps. It should be updated regularly and is intended to help developers quickly understand 
where development should continue.

# Current phase

## Phase 6 – Application polish

# Current milestone

## Milestone 6.2 – Production Runtime

# Current task

- Configure OpenIddict production credentials.
  - Define the production signing credential strategy.
  - Define the production encryption credential strategy.
  - Register production signing credentials.
  - Register production encryption credentials.
  - Separate development and production credential registration.
  - Prevent development credentials being used outside Development.
  - Verify token signing.
  - Verify token encryption.
  - Verify application startup using production credentials.

# Remaining milestone tasks

- Configure persistent Data Protection.
- Implement startup validation.

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
