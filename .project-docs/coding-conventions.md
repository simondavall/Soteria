This document defines the coding conventions used throughout the project. It records agreed naming conventions, layout preferences and implementation style so that the codebase remains consistent regardless of who contributes to it.

# Naming
- Async methods end with Async.
- Interfaces prefixed with I.

# Formatting

## C#

- Prefer compact formatting where readability is preserved.
- Keep parameter lists and method invocations on a single line when they remain comfortably readable.
- Avoid introducing vertical whitespace unless it separates logical blocks.
- Wrap expressions only when line length or readability genuinely benefits.
- Prefer compact object construction where the intent remains clear.
- Optimise for scanability rather than minimising line length.

## Razor

- Prefer vertically stacked component attributes where this improves scanability.
- Place one attribute per line for components with several attributes.
- Keep short, simple components on one line where they remain easy to read.
- Use indentation and whitespace to make component structure and nesting clear.
- Do not apply compact C# formatting preferences to Razor component attributes.

# Components
- Code-behind by default.
- Keep Razor markup declarative.

# Dependency Injection
- Constructor injection where possible.
- Property injection only for Blazor components.

# Validation
- Use MudForm for interactive MudBlazor editors.
- Use FluentValidation for interactive editor validation.
- Keep validation rules in dedicated validator classes.
- Use EditForm with built-in Blazor inputs for static SSR Identity workflows.
- Prefer field-level validation messages over ValidationSummary where practical.
- Display persistence and business-rule validation failures at dialog level.

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
