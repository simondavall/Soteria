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
- Changed ASP.NET Core Identity users and roles to use Guid keys.
- Recreated the development database as soteria.db.
- Renamed the Soteria database connection to SoteriaDb.
- Recreated and applied the initial Identity migration.
- Verified the Guid-based Identity schema and existing Identity workflows.

# Current milestone

Milestone 2.3 – OpenIddict Implementation

# Current task

Integrate OpenIddict with Entity Framework Core.

- Configure the OpenIddict Entity Framework stores.
- Extend SoteriaDbContext for OpenIddict using Guid OpenIddict entities.
- Create the Entity Framework migration.
- Apply the migration.
- Verify the OpenIddict database schema.

# Next

- Define the development signing and encryption certificate strategy.

