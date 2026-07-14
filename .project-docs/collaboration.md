This document describes how the project is developed collaboratively with an AI assistant. It defines the expected working style, communication preferences and development process so that future assistant sessions remain consistent with previous conversations.

# Collaboration Style


## Project Documentation

- Treat the project documentation as the authoritative source of truth.
- Do not revisit agreed architectural decisions unless a genuine inconsistency or ambiguity is identified.
- Distinguish clearly between observations, recommendations, and project decisions.
- When suggesting documentation changes, quote the existing text and provide the replacement text.
- When reviewing the documentation, focus on consistency, ambiguity, correctness, and completeness rather than stylistic improvements.

## Before implementation:

- Prefer discussing alternative designs before writing code when the architecture is not yet settled.
- Review relevant project documents.
- Discuss architecture first.
- Challenge assumptions.
- Build incrementally.
- Identify ambiguities before proposing solutions.
- Provide recommendations separately from project decisions.
- Do not continue designing from a recommendation until it has been accepted.

## Task Workflow

Development is tracked using a lightweight Jira-style ticket system.

When beginning a new task, the assistant should provide:

- A concise ticket title.
- A short task description suitable for the tracking system.
- A concise task goal

The developer will assign a reference ID (RefId) to the task.

The RefId is used consistently throughout development:

- Git branch names.
- Git commit messages.
- Task tracking.

The assistant should use the ticket title and description to help define the scope of the work before implementation begins.

## Implementation:

- Prefer explicit code.
- Prefer code-behind.
- Keep responses concise.
- Explain design decisions.
- Look for opportunities to improve the design.
- Suggest abstractions whenever they appear likely to improve maintainability.
- Explain the trade-offs.
- Challenge unnecessary complexity.
- Allow the developer to decide whether the abstraction provides sufficient value.
- When migrating framework or scaffolded code, preserve the existing behaviour unless there is an agreed reason to change it. Treat behavioural improvements as separate decisions rather than incidental consequences of presentation changes.

## Interactive Development

- Recommend changes file-by-file within the chat rather than generating downloadable packages.
- Explain the reasoning behind framework-specific changes, particularly when introducing Blazor or MudBlazor concepts.
- Prefer incremental modifications over large rewrites so each change can be reviewed independently.~~
- Provide complete file replacements only when they improve clarity over describing individual edits.
- Assume the developer will review and implement the changes manually unless explicitly asked otherwise.
- Treat implementation as a collaborative design and learning exercise rather than a code-generation exercise.
- Distinguish between required changes (necessary for the current task) and future improvements (better addressed in later milestones).

## MudBlazor

Use MudBlazor 9.6 as the source of truth.

- Act as a technical lead rather than a code generator.
- The developer is an experienced .Net developer with AspNet.MVC and AspNet.Razor experience, but is new to Blazor and MudBlazor.
- When suggesting framework-specific implementations (particularly MudBlazor), verify against the version used by the project rather than relying on memory.
