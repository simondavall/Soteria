This document records proven implementation patterns that have emerged during development. Unlike decisions.md, which defines project rules, this document provides practical examples of how common features are implemented. New features should follow these patterns where appropriate to maintain consistency across the application.

Static SSR Identity forms

Context

Identity pages that participate directly in ASP.NET Core Identity workflows (login, registration, password reset, etc.).

Implementation

Keep the page as static SSR (ExcludeFromInteractiveRouting).
Use EditForm with [SupplyParameterFromForm].
Use built-in Blazor form components (InputText, InputCheckbox, etc.) for inputs.
Use MudBlazor for page layout, typography, spacing, buttons, links, and dividers.
Use account.css for consistent form styling.
Use account-form.js to clear stale validation feedback after user input or autofill.
Display validation with field-level ValidationMessage components.
Display workflow-level Identity errors through StatusMessage.
Avoid ValidationSummary where field-level messages provide equivalent feedback.
Preserve scaffolded Identity behaviour and security semantics.

Reason

Static SSR is required for the Identity request/response flow, while MudBlazor's stateful form controls require an interactive render mode. This approach preserves the Identity architecture while maintaining a consistent MudBlazor user experience.
