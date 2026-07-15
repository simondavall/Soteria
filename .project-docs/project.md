This document provides a high-level overview of the project. It describes what the application is, why it exists, the technologies it uses, and the overall design philosophy. It should help a developer understand the purpose and scope of the project before looking at implementation details.

# Project overview
Soteria is a self-hosted Identity and Access Management (IAM) system for a collection of privately hosted web applications under common ownership.

The project exists to eliminate the need for each application to maintain its own user accounts, authentication, and authorisation. Instead, applications delegate these responsibilities to Soteria, allowing users to have a single identity that can be used across multiple applications.

Each consuming web application is registered with Soteria as a client application. Applications authenticate users using OpenID Connect, with Soteria acting as the trusted identity provider. Soteria is also the source of truth for application access, roles, and claims, allowing consuming applications to trust the identity information they receive and concentrate on their own business logic.

Soteria provides a central administration interface for managing users, client applications, application access, roles, claims, and other identity-related features. Users are also able to manage their own accounts through self-service features, with the exact capabilities evolving as the project develops.

The initial focus is on self-hosted and privately operated applications rather than providing a general-purpose public identity platform. The project aims to follow established identity standards and security practices while remaining simple to understand, maintain, and extend.

In addition to solving a practical problem, Soteria serves as a learning project for OpenIddict, Blazor, and MudBlazor. These technologies are adopted to build experience with modern authentication and web application development while maintaining a preference for clear, explicit, and maintainable solutions.

# Goals
The primary goals of the project are:
- Provide a secure and efficient user and client administration experience.
- Maintain a consistent interface across account, user, client, role, and security workflows.
- Optimise for common administrative tasks while making security-sensitive actions explicit.
- Minimise opportunities for administrators to act on the wrong client or user.

# Technology stack

## Backend
- .NET 10
- ASP.NET Core Blazor Web App
- Entity Framework Core 10
- OpenIddict
- SQLite

## Frontend
- MudBlazor 9.6
- Minimal JavaScript

# High-level architecture
The application uses a Vertical Slice Architecture.

Each feature owns its own:

- Pages
- Components
- Services

Business logic lives within feature services.

Entity Framework entities are used directly where appropriate.

The application intentionally avoids unnecessary framework abstractions and favours explicit code that is easy to understand and debug.

Shared functionality is actively sought once it has emerged from multiple successful implementations.

# Folder structure
```
Soteria
│
├── Components
│   ├── Account
│   ├── Features
│   ├── Shared
│   └── Layout
├── Data
│   ├── ApplicationUser
│   └── SoteriaDbContext
└── Docs
```

Features contain all UI and services relating to a single content area.

Shared contains reusable UI components.

Data contains the generated Entity Framework model.

Docs contains project documentation.

# Design principles
The project values:

- Explicit behaviour over hidden behaviour.
- Readability over cleverness.
- Purposeful abstraction over repeated implementation.
- Abstractions that remove mechanical duplication while preserving explicit behaviour.
- Small, focused components and services.
- Clear ownership of responsibilities.
- Consistent user experience.

# Documentation overview
| Document              | Purpose                                                   |
|-----------------------|-----------------------------------------------------------|
| project.md            | What the project is.                                      |
| roadmap.md            | What capabilities are delivered, and in what order.       |
| delivery-plan.md      | How we intend to deliver the current and upcoming phases. |
| current-state.md      | Current progress and next feature.                        |
| decisions.md          | Architectural decisions and project rules.                |
| patterns.md           | Proven implementation patterns.                           |
| backlog.md            | Future work and enhancements.                             |
| collaboration.md      | How the assistant should collaborate.                     |
| coding-conventions.md | Coding style and conventions.                             |
| decisions-log.md      | Record of important architectural decisions.              |

# Non-goals
The project deliberately does not aim to:

- Implement unnecessary architectural layers.
- Hide Entity Framework behind repositories.
- Optimise for hypothetical future requirements.