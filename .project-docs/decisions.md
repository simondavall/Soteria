This document captures the architectural and design decisions that guide development of the project. These decisions are considered project rules and should be followed consistently unless there is a compelling reason to change them. The document focuses on long-lived decisions rather than implementation details or current progress.

# Architecture
- Use Vertical Slice Architecture.
- Organise the application by feature rather than technical layer.
- Keep business logic within feature services.
- Shared functionality should be actively considered whenever patterns emerge.
- Introduce abstractions that remove repeated implementation while preserving explicit behaviour.
- Prefer small abstractions with a single responsibility.
- Avoid abstractions that hide application flow or introduce unnecessary indirection.

# Data
- Use Entity Framework Core.
- Feature services inject SoteriaDbContext directly.
- Use EF Core entities directly where appropriate.
- Avoid introducing DTOs or mapping layers unless they provide a clear benefit.
- Do not introduce a generic repository layer.

# Dependencies
- Prefer first-party .NET features where practical.
- No MediatR.
- No AutoMapper.
- Use MudBlazor as the primary UI framework.
- Wrap third-party libraries behind project components where practical.

# Feature Design
- Each feature owns its pages, components and services.
- Pages coordinate workflow.
- Components encapsulate reusable UI.
- Feature services own persistence and business logic.
- Avoid business logic in Razor markup.

# Components
- Prefer Razor code-behind for pages and larger components.
- Keep Razor markup declarative.
- Shared components are first-class citizens.
- Extract shared components only after duplication appears.
- Shared components should expose an API consistent with MudBlazor where practical.
- Shared components should be preferred over repeated UI patterns once a pattern has been proven.

# Editors
> **Review:** Revisit this section once the first data editing workflows have been implemented. At that point we can decide whether the guidance is generally applicable or whether the section should be renamed (for example, to Management or Administration).
- Edit entities in dialogs where practical.
- Keep simple editors on a single page.
- Use tabs only when they meaningfully improve organisation (for example, large forms or child collections).
- Place Save and Cancel actions at the bottom right.
- Editors validate before closing.

# Validation
- Validation belongs in the UI layer.
- Use MudBlazor form validation where practical.
- Shared input components should participate in form validation.
- Feature services may assume UI validation has completed, but remain responsible for enforcing business rules, authorisation, and application security.
- Prefer extending shared components rather than duplicating validation logic.

# Styling
- MudBlazor owns the application theme.
- Third-party components should match the MudBlazor look and feel.
- Keep project styling in project CSS rather than modifying third-party libraries.

# User Experience
- Optimise for efficient identity and access management.
- Minimise unnecessary page navigation.
- Prefer inline editing where it improves workflow.
- Use icon buttons with tooltips for common actions.
- Provide immediate visual feedback after user actions.

# Visual Language
| Element             | Style                 |
| ------------------- | --------------------- |
| Page title          | `MudText Typo.h4`     |
| Primary action      | Filled Primary button |
| Secondary action    | Outlined button       |
| Delete              | Error icon button     |
| Save                | Bottom right          |
| Cancel              | Bottom left           |
| Success             | Snackbar              |
| Delete confirmation | Dialog                |

# Shared Patterns
- Encourage abstractions that remove mechanical duplication.
- Discourage abstractions that hide behaviour or obscure control flow.
- Optimise for maintainability over minimal code.
- Build abstractions from proven implementations rather than speculation.

# Philosophy
- Prefer explicit behaviour to hidden behaviour.
- Prefer readability to cleverness.
- Introduce abstractions only after they have demonstrated clear value.
- Prefer abstractions that reduce duplication without hiding behaviour.
- Optimise for maintainability.
- Focus effort where it provides real value.

