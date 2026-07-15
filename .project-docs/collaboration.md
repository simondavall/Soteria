This document describes how the project is developed collaboratively with an AI assistant. It defines the expected working style, communication preferences and development process so that future assistant sessions remain consistent with previous conversations.

# Collaboration Style

## Project Documentation

- Treat the project documentation as the authoritative source of truth.
- Do not revisit agreed architectural decisions unless a genuine inconsistency or ambiguity is identified.
- Distinguish clearly between observations, recommendations, and project decisions.
- When suggesting documentation changes, quote the existing text and provide the replacement text.
- When reviewing the documentation, focus on consistency, ambiguity, correctness, and completeness rather than stylistic improvements.

## Before implementation

- Review the relevant project documentation before proposing changes.
- Ask for updated file uploads if required, don't rely of stale information or long memory.
- Prefer discussing alternative designs before writing code when the architecture is not yet settled.
- Treat established project decisions as the default unless a genuine inconsistency or ambiguity is identified.
- Discuss alternatives before implementation when significant design decisions remain unresolved.
- Challenge assumptions where appropriate.
- Identify ambiguities, unknowns and decisions before proposing solutions.
- Distinguish clearly between observations, recommendations and agreed decisions.
- Do not continue designing from a recommendation until it has been accepted.

## Task Workflow

Development is tracked using a lightweight Jira-style ticket system.

When beginning a new task, the assistant should provide:

- A concise ticket title.
- A short task description suitable for the tracking system.
- A concise task goal
- A scope for the task

The developer will assign a reference ID (RefId) to the task.

The RefId is used consistently throughout development:

- Git branch names.
- Git commit messages. (Always past tense, in the form '<lowercase refId>: <commit message>)
- Task tracking.

The assistant should use the ticket title and description to help define the scope of the work before implementation begins.

## Implementation

- Prefer explicit code.
- Prefer code-behind for pages and larger components.
- Keep responses concise.
- Explain design decisions when they introduce new concepts or establish new patterns.
- As understanding grows, reduce repeated explanation of previously agreed approaches.
- Actively look for opportunities to improve maintainability.
- Recommend abstractions only after repeated successful implementations demonstrate clear value.
- Explain the trade-offs of proposed abstractions.
- Challenge unnecessary complexity.
- Preserve established behaviour unless there is an agreed reason to change it.
- Treat behavioural improvements as explicit design decisions rather than incidental implementation changes.

## Verification

- Provide a concise verification checklist for completed work.
- Verification should focus on observable behaviour rather than implementation details.
- Update verification checklists when defects are discovered so fixes become permanent regression tests.
- Prefer verifying complete user workflows rather than isolated implementation details.

## Working Rhythm

Development naturally progresses through distinct phases.

### Exploration
- Slow the pace while requirements, architecture and implementation patterns are being established.
- Discuss alternatives before implementation.
- Expect frequent review and verification.

### Consolidation
- Once a pattern has been proven, implement subsequent work more confidently with increased pace.
- Avoid repeatedly discussing previously agreed decisions.
- Implement similar work together where it follows an established pattern.

### Refinement
- Continue identifying improvements.
- Separate refinements from the primary implementation unless they are required to complete the current task.

## Interactive Development

- Recommend changes incrementally unless a complete replacement is clearer.
- Provide complete file replacements when they improve clarity over describing individual edits.
- Assume the developer will review and apply changes manually unless asked otherwise.
- Treat implementation as a collaborative design exercise rather than code generation.
- Distinguish between changes required for the current task and improvements that can be deferred.

## Continuous Improvement

- Adapt the level of explanation to the developer's growing familiarity with the project and its technologies.
- Increase implementation pace as shared understanding develops.
- Avoid re-opening settled decisions unless new evidence justifies doing so.
- Capture new working practices in the project documentation once they have proven successful.

## MudBlazor

Use MudBlazor 9.6 as the source of truth.

- Act as a technical lead rather than a code generator.
- The developer is an experienced .Net developer with AspNet.MVC and AspNet.Razor experience, but is new to Blazor and MudBlazor.
- When suggesting framework-specific implementations (particularly MudBlazor), verify against the version used by the project rather than relying on memory.
