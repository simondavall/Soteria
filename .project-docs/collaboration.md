This document describes how the project is developed collaboratively with an AI assistant. It defines the expected working style, communication preferences and development process so that future assistant sessions remain consistent with previous conversations.

# Collaboration Style

## Project Documentation

- Treat the project documentation as the authoritative source of truth.
- Do not revisit agreed architectural decisions unless a genuine inconsistency or ambiguity is identified.
- Distinguish clearly between observations, recommendations, and project decisions.
- When suggesting documentation changes, quote the existing text and provide the replacement text.
- When reviewing the documentation, focus on consistency, ambiguity, correctness, and completeness rather than stylistic improvements.
- Provide document updates that are easy for the user to apply in the established format.
- Recommend updates only for documents affected by the completed task.
- Prefer a single replacement covering adjacent sections rather than multiple small replacements where it improves readability.

Use the following format when suggesting document changes:
- Replace \<existing section\> with \<replacement section\>.
- Add \<new section\> after / before \<existing section\>.
- Use a complete document replacement only when a document has been substantially restructured.

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

The assistant should complete each task using the following workflow:

1. Discuss the implementation where architectural or design decisions remain. Do not revisit established project decisions unless a genuine inconsistency or ambiguity is identified.
2. Update affected project documentation immediately when the discussion settles a project decision, scope clarification, responsibility boundary or delivery-plan change. The documentation should describe the implementation that is about to be performed before implementation begins.
3. Define the Jira ticket after the discussion phase so that its title, description, goal and scope reflect the agreed implementation. The developer will assign the RefId.
4. Provide the complete implementation together with the verification checklist in a single response, pausing only where new information or a genuine decision is required.
5. Once verification has passed, recommend updates that record the completed implementation and advance the documented project state.

Discussion-phase documentation updates may include:

- architectural decisions;
- Jira scope and task-boundary clarifications;
- delivery-plan changes;
- roadmap changes;
- responsibility clarifications;
- implementation requirements established during discussion.

Completion-phase documentation updates may include:

- completed work in current-state.md;
- the next current task;
- implementation decisions discovered during development;
- proven implementation patterns;
- permanent regression verification.

Use explicit copy-ready recommendations in the established format:

- Replace <existing section> with <replacement section>.
- Add <new section> after / before <existing section>.
- Where adjacent sections are changing, prefer a single replacement covering all affected sections.

The task is not considered complete until verification has passed and the required project documentation updates have been applied or recommended.

Verification should include confirming that:
- the application builds successfully (where applicable);
- the application starts successfully and remains runnable after the changes;
- previously completed behaviour required by the current task continues to work;
- the new behaviour introduced by the task behaves as expected.

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

### Documentation Review

At the end of each architectural discussion or implementation task:

- Recommend any project documentation that should be updated before the task is considered complete.
- Identify whether the work establishes a new implementation pattern suitable for patterns.md.
- Identify whether any significant architectural decisions should be recorded in decisions-log.md.
- Highlight inconsistencies or stale documentation discovered during the task.
- Recommend starting a new conversation when the current session becomes long enough that a fresh session would improve collaboration, provided the documentation is sufficient for another assistant to continue the work with minimal loss of context.

## MudBlazor

Use MudBlazor 9.6 as the source of truth.

- Act as a technical lead rather than a code generator.
- The developer is an experienced .Net developer with AspNet.MVC and AspNet.Razor experience, but is new to Blazor and MudBlazor.
- When suggesting framework-specific implementations (particularly MudBlazor), verify against the version used by the project rather than relying on memory.
