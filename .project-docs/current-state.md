This document provides a snapshot of the current implementation state of the project. It records completed work, the feature currently being developed, and the next expected steps. It should be updated regularly and is intended to help developers quickly understand where development should continue.

# Current phase

Phase 2 – OpenID Connect Provider Foundation

# Completed

- Established the initial project structure.
- Created the project documentation.
- Defined the project vision and roadmap.
- Added and configured MudBlazor 9.6.
- Established the initial application theme.
- Configured the MudBlazor providers.
- Established the shared application layout.
- Migrated the built-in ASP.NET Core Identity UI to the project UI conventions.
- Added development email sender for Identity.
- Preserved ASP.NET Core Identity behaviour and static SSR workflows.
- Established the project Identity implementation patterns.
- Reviewed and restructured the project roadmap and delivery planning model.
- Defined the OpenID Connect provider architecture.
- Defined the authentication flow between Soteria and consuming applications.
- Defined the initial client application model.
- Defined the boundary between hard-coded configuration and future configuration.
- Defined and created the reference web application.
- Defined and created the reference Resource API.
- Verified communication between the reference web application and the reference Resource API.
- Added the required OpenIddict packages.

# Current milestone

Milestone 2.3 – OpenIddict Implementation

# Current task

Use Guid keys for ASP.NET Core Identity.

- Change ApplicationUser to use a Guid key.
- Configure Identity roles to use Guid keys.
- Update SoteriaDbContext and Identity registration.
- Update code that assumes string Identity identifiers.
- Recreate the development database using soteria.db.
- Create the Entity Framework migration.
- Apply the migration.
- Verify existing Identity workflows and the database schema.

# Next

- Integrate OpenIddict with Entity Framework Core.

