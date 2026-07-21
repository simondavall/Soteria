This document records proven implementation patterns that have emerged during development. Unlike decisions.md, which defines project rules, this document provides practical examples of how common features are implemented. New features should follow these patterns where appropriate to maintain consistency across the application.

# Static SSR Identity forms

## Context
Identity pages that participate directly in ASP.NET Core Identity workflows (login, registration, password reset, etc.).

## Implementation
- Keep the page as static SSR (ExcludeFromInteractiveRouting).
- Use EditForm with [SupplyParameterFromForm].
- Use built-in Blazor form components (InputText, InputCheckbox, etc.) for inputs.
- Use MudBlazor for page layout, typography, spacing, buttons, links, and dividers.
- Use account.css for consistent form styling.
- Use account-form.js to clear stale validation feedback after user input or autofill.
- Display validation with field-level ValidationMessage components.
- Display workflow-level Identity errors through StatusMessage.
- Avoid ValidationSummary where field-level messages provide equivalent feedback.
- Preserve scaffolded Identity behaviour and security semantics.
- Treat encoded query-string tokens as untrusted input and handle decoding failures without exposing exceptions.

## Reason
Static SSR is required for the Identity request/response flow, while MudBlazor's stateful form controls require an interactive render mode. This approach preserves the Identity architecture while maintaining a consistent MudBlazor user experience.

# OpenIddict endpoints
When implementing OpenIddict endpoints that require application logic:

• Enable the appropriate ASP.NET Core pass-through.
• Map the endpoint explicitly using endpoint routing.
• Perform application-specific work.
• Complete the protocol using the OpenIddict authentication scheme.
• Keep protocol validation inside OpenIddict and business logic inside Soteria.

## Shared Provider Configuration

### Problem

Multiple workflows need to configure an OpenIddict application using the same provider defaults. Duplicating the configuration increases the risk of the provider behaviour diverging over time.

### Pattern

Place the shared provider configuration into a small internal helper that applies the common configuration to an `OpenIddictApplicationDescriptor`.

Individual workflows remain responsible for supplying their own application-specific values (for example client identifier, display name, client secret and redirect URIs) before creating or updating the application.

### Benefits

- Maintains a single source of truth for provider defaults.
- Keeps bootstrap registration and administrative workflows aligned.
- Reduces maintenance effort when provider defaults evolve.
- Avoids introducing unnecessary service abstractions while still removing duplicated implementation.

# MudBlazor Administrative Editors

## Context

Interactive administration dialogs that create or edit entities.

## Pattern

- Use MudForm for interactive validation.
- Use FluentValidation for validation rules.
- Keep validation in dedicated validator classes.
- Inject FluentValidation's `IValidator<T>` into feature services.
- Use a small MudBlazor adapter interface only where required to integrate with `MudForm`.
- Keep persistence lookups used by validation behind small query services rather than injecting feature services into validators.
- Display server-side validation failures at dialog level while leaving field validation to MudBlazor.
- Normalise request values immediately before persistence.

## Benefits

- Separates UI validation from persistence.
- Avoids circular service dependencies.
- Keeps validators reusable.
- Keeps feature services focused on business behaviour.
- Produces consistent validation behaviour across administrative editors.