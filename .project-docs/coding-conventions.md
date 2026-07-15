This document defines the coding conventions used throughout the project. It records agreed naming conventions, layout preferences and implementation style so that the codebase remains consistent regardless of who contributes to it.

# Naming
- Async methods end with Async.
- Interfaces prefixed with I.

# Layout
- Use primary constructors where appropriate.
- Prefer collection expressions.
- Prefer expression-bodied members only when clearer.

# Components
- Code-behind by default.
- Keep Razor markup declarative.

# Dependency Injection
- Constructor injection where possible.
- Property injection only for Blazor components.

# Validation
- Use MudForm for interactive MudBlazor editors.
- Use EditForm with built-in Blazor inputs for static SSR Identity workflows.
- Prefer field-level validation messages over ValidationSummary where practical.

# Async
- Prefer async all the way.
- Event handlers should explicitly await asynchronous methods.

# Nullable
- Nullable enabled.
- Avoid ! unless genuinely required.

# Comments
- Prefer self-documenting code.
- Comment intent, not implementation.

# Abstraction
- Prefer abstractions that remove repeated implementation.
- Keep abstractions small and focused.
- Prefer composition over inheritance where both provide similar clarity.
- Base classes are appropriate where they remove mechanical duplication without restricting feature behaviour.
