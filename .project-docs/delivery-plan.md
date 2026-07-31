# Delivery Plan

This document expands the roadmap into implementation milestones and tasks.

Unlike the roadmap, which describes the long-term delivery of the project, this document 
records the expected sequence of implementation work.

The roadmap should remain relatively stable.

The delivery plan is expected to evolve as implementation progresses and architectural 
understanding improves.

Tasks listed here are intentionally concise. Detailed scope, goals and implementation 
notes belong in the Jira task for the relevant RefId.

---

# Phase 2 – OpenID Connect Provider Foundation

## ✓ Milestone 2.1 – Provider Architecture

- ✓ Review and restructure the project roadmap and delivery planning model.
- ✓ Define the OpenID Connect provider architecture.
- ✓ Define the authentication flow between Soteria and consuming applications.
- ✓ Define the initial client application model.
- ✓ Define the boundary between hard-coded configuration and future configuration.

---

## ✓ Milestone 2.2 – Reference Applications

(Initially set up with local independent authentication, which will be replaced with OpenID 
Connect in Milestone 2.3.)

- ✓ Define and create the reference web application with local ASP.NET Core Identity.
- ✓ Define and create the reference resource API.
- ✓ Configure and verify communication between the reference web application and the 
reference resource API.

---

## Milestone 2.3 – OpenIddict Implementation

- ✓ Add the OpenIddict packages.
  - ✓ Add the ASP.NET Core integration package.
  - ✓ Add the Entity Framework Core integration package.
  - ✓ Verify the application builds and existing Identity behaviour remains unchanged.

- ✓ Use Guid keys for ASP.NET Core Identity.
  - ✓ Change ApplicationUser to use a Guid key.
  - ✓ Configure Identity roles to use Guid keys.
  - ✓ Update SoteriaDbContext and Identity registration.
  - ✓ Update code that assumes string Identity identifiers.
  - ✓ Recreate the development database using soteria.db.
  - ✓ Create or replace the Entity Framework migration.
  - ✓ Apply the migration.
  - ✓ Verify existing Identity workflows and the database schema.

- ✓ Integrate OpenIddict with Entity Framework Core.
  - ✓ Configure the OpenIddict Entity Framework stores.
  - ✓ Extend SoteriaDbContext for OpenIddict using Guid OpenIddict entities.
  - ✓ Create the Entity Framework migration.
  - ✓ Apply the migration.
  - ✓ Verify the OpenIddict database schema.

- ✓ Define the development signing and encryption certificate strategy.
  - ✓ Determine how development certificates are generated, stored or loaded.
  - ✓ Define separate signing and encryption credential requirements.
  - ✓ Define certificate persistence and reuse between application restarts.
  - ✓ Define safeguards against using development credentials outside development.
  - ✓ Record the agreed strategy.

- ✓ Register the OpenIddict server and establish the initial provider configuration.
  - ✓ Register the OpenIddict server services.
  - ✓ Register the ASP.NET Core host integration.
  - ✓ Configure development signing credential.
  - ✓ Configure development encryption credential.
  - ✓ Verify the server configuration and credentials load successfully.

- ✓ Configure the OpenID Connect endpoint pipeline.
  - ✓ Verify the authorization endpoint has basic default configuration.
  - ✓ Verify the token endpoint has basic default configuration.
  - ✓ Verify the discovery endpoint and signing-key metadata.
  - ✓ Configure only endpoints supported by the current runnable provider implementation.
  - ✓ Verify the published endpoint metadata.

- ✓ Complete the supported protocol configuration.
  - ✓ Configure Authorization Code Flow.
  - ✓ Configure PKCE requirements.
  - ✓ Disable unsupported flows.
  - ✓ Verify the advertised server capabilities.

- ✓ Register the initial API scope.
  - ✓ Define the scope name.
  - ✓ Associate the scope with the Reference API resource.
  - ✓ Register the scope.

- ✓ Register the reference web application as an OpenID Connect client.
  - ✓ Define the client identifier.
  - ✓ Define the display name.
  - ✓ Configure the client type.
  - ✓ Configure redirect URIs.
  - ✓ Configure authorization and token endpoint permissions.
  - ✓ Configure grant-type permissions.
  - ✓ Configure response-type permissions.
  - ✓ Configure supported scopes.
  - ✓ Configure the consent type.
  - ✓ Configure PKCE requirements.
  - ✓ Verify the client registration.

- ✓ Verify the OpenIddict provider configuration.
  - ✓ Verify discovery metadata.
  - ✓ Verify endpoint availability.
  - ✓ Verify client registration.
  - ✓ Verify scope registration.
  - ✓ Verify unsupported requests are rejected.

---

## Milestone 2.4 – Authentication Workflow

- ✓ Connect OpenIddict to ASP.NET Core Identity.
  - ✓ Configure ASP.NET Core Identity as the authentication mechanism.
  - ✓ Configure the Identity application cookie.
  - ✓ Enable OpenIddict authorization endpoint pass-through to Soteria.
  - ✓ Challenge unauthenticated users through the Soteria login workflow.
  - ✓ Preserve the complete authorization request during authentication.
  - ✓ Verify authenticated users reach the Soteria authorization endpoint via the OpenIddict 
  authorization pipeline.

- ✓ Implement the authorisation workflow.
  - ✓ Handle the authorization request.
  - ✓ Determine whether the user must authenticate.
  - ✓ Determine whether consent is required.
  - ✓ Create the OpenIddict claims principal.
  - ✓ Grant the validated requested scopes.
  - ✓ Resolve resources from granted scopes.
  - ✓ Return the authorised principal to OpenIddict.
  - ✓ Verify successful Authorization Code issuance.

- ✓ Define the initial identity claims.
  - ✓ Define the initial ID token claims.
  - ✓ Define the initial access token claims.
  - ✓ Define claim destinations.
  - ✓ Define the Reference API audience.

- ✓ Configure token issuance.
  - ✓ Issue identity claims.
  - ✓ Issue access tokens.
  - ✓ Issue refresh tokens.
  - ✓ Verify the issued tokens.

- ✓ Configure refresh-token lifecycle.
  - ✓ Define the refresh-token strategy.
  - ✓ Configure refresh-token lifetime.
  - ✓ Configure access-token renewal.
  - ✓ Verify rolling refresh-token rotation.
  - ✓ Verify consent-required behaviour remains unchanged.

- ✓ Configure consent behaviour.
  - ✓ Define consent behaviour for managed client applications.
  - ✓ Configure the agreed consent behaviour.

- ✓ Replace the reference web application's local authentication with OpenID Connect.
  - ✓ Configure OpenID Connect authentication.
  - ✓ Remove local ASP.NET Core Identity authentication.
  - ✓ Preserve the application-local authentication session.

- ✓ Implement automatic access-token renewal using refresh tokens.
  - ✓ Detect expired access tokens.
  - ✓ Renew access tokens using the refresh token.
  - ✓ Persist replacement refresh tokens.
  - ✓ Retry failed API requests after successful renewal.

- ✓ Support logout.
  - ✓ Configure the OpenIddict end-session endpoint.
  - ✓ Configure end-session endpoint pass-through or an equivalent OpenIddict request handler.
  - ✓ Configure the reference client's post-logout redirect URI.
  - ✓ Configure any required end-session endpoint permission.
  - ✓ Configure RP-initiated logout.
  - ✓ Sign the user out of Soteria.
  - ✓ Sign the user out of the reference application.
  - ✓ Verify post-logout redirect behaviour.

---

## Milestone 2.5 – End-to-End Verification

- ✓ Verify successful authentication.
  - ✓ Authenticate the reference web application.
  - ✓ Verify successful sign-in.
  - ✓ Verify authenticated application access.

- ✓ Verify unsuccessful authentication scenarios.
  - ✓ Verify anonymous access.
  - ✓ Verify invalid credentials.
  - ✓ Verify unauthorised client requests.
  - ✓ Verify invalid redirect URIs.

- ✓ Verify protected API access.
  - ✓ Call the Reference API using an access token.
  - ✓ Verify successful API authorisation.
  - ✓ Verify rejected requests without an access token.
  - ✓ Verify rejected requests with an invalid access token.

- ✓ Verify access-token renewal.
  - ✓ Verify refresh-token use.
  - ✓ Verify renewed access tokens.
  - ✓ Verify expired access-token handling.

- ✓ Verify logout.
  - ✓ Verify reference application logout.
  - ✓ Verify Soteria logout.
  - ✓ Verify access after logout is denied.

---

# Phase 3 – Client Application Management

## Milestone 3.1 – Client Administration

- ✓ Create the client application management feature.
  - ✓ Define authenticated administration navigation.
  - ✓ Create the authenticated client application list page layout.
  - ✓ Create the authenticated client details page layout.
  - ✓ Define the client management navigation workflow.

- ✓ Implement client application listing.
  - ✓ Retrieve registered OpenIddict applications.
  - ✓ Display application summary information.
  - ✓ Display client type and consent type.
  - ✓ Display application status (currently Active for all applications; enabled/disabled state will be introduced in Milestone 3.2).
  - ✓ Verify application listing.

- ✓ Implement client application details.
  - ✓ Retrieve the selected OpenIddict application.
  - ✓ Display client type and consent configuration.
  - ✓ Display configured endpoint permissions.
  - ✓ Display configured grant type permissions.
  - ✓ Display configured response type permissions.
  - ✓ Display configured scopes.
  - ✓ Display configured redirect URIs.
  - ✓ Display configured post-logout redirect URIs.
  - ✓ Verify application details.

---

## Milestone 3.2 – Client Management

- ✓ Create client applications.
  - ✓ Define the client creation workflow.
  - ✓ Create OpenIddict applications.
  - ✓ Validate required client information.
  - ✓ Verify application creation.

- ✓ Edit client applications.
  - ✓ Define the client edit workflow.
  - ✓ Update the display name.
  - ✓ Replace the client secret.
  - ✓ Update the client host.
  - ✓ Recalculate the redirect URI and post-logout redirect URI from the updated client host.
  - ✓ Preserve the immutable client identifier.
  - ✓ Verify application updates.

- ✓ Enable and disable client applications.
  - ✓ Define the enabled state.
  - ✓ Persist the enabled state on the client application.
  - ✓ Prevent disabled applications from starting new authentication.
  - ✓ Prevent disabled applications from obtaining new tokens.
  - ✓ Allow existing access tokens to remain valid until expiry.
  - ✓ Display application status.
  - ✓ Verify enabled and disabled behaviour.

- ✓ Implement user-friendly OpenID Connect authentication error handling.
  - ✓ Define the provider-owned OpenID Connect error-handling process.
  - ✓ Present browser-facing authorization errors through a shared Soteria error page.
  - ✓ Map recognised OpenID Connect protocol errors to user-friendly messages.
  - ✓ Display safe fallback content for unrecognised errors.
  - ✓ Keep protocol validation within OpenIddict and presentation within Soteria.
  - ✓ Verify disabled-client authentication displays the friendly error page.

---

# Phase 4 – Identity Management

## Milestone 4.1 – User Administration

- ✓ Create the user administration feature.
  - ✓ Define authenticated administration navigation.
  - ✓ Create the authenticated user list page layout.
  - ✓ Create the authenticated user details page layout.
  - ✓ Define the user administration navigation workflow.

- ✓ Implement user listing.
  - ✓ Retrieve registered users.
  - ✓ Display user summary information.
  - ✓ Display account status.
  - ✓ Support searching users.
  - ✓ Verify user listing.

- ✓ Implement user details.
  - ✓ Retrieve the selected user.
  - ✓ Display account information.
  - ✓ Display profile information.
  - ✓ Display email information.
  - ✓ Display lockout information.
  - ✓ Verify user details.

- ✓ Create user accounts.
  - ✓ Define the administrative registration workflow.
  - ✓ Create new user accounts.
  - ✓ Support registration of existing users.
  - ✓ Add placeholder to associate users with one or more client applications.
  - ✓ Send the account confirmation email.
  - ✓ Verify user registration.

- ✓ Edit user administration workflow
  - ✓ Display all user details in a read-only edit dialog.
  - ✓ Allow administrators to unlock locked user accounts.
  - ✓ Display a Permissions placeholder for future Phase 5 implementation.
  - ✓ Persist unlock changes only when Save is selected.

---

# Phase 5 – Application Authorisation

## ✓ Milestone 5.1 – Authorisation Persistence Model

- ✓ Create the Authorization persistence model.
  - ✓ Create the System Role persistence model.
    - ✓ Create the `SystemRole` entity.
    - ✓ Create the `UserSystemRole` assignment entity.
    - ✓ Enforce unique System Role names.
    - ✓ Enforce unique user and System Role assignments.

  - ✓ Create the Client Membership persistence model.
    - ✓ Create the `ClientMembership` entity.
    - ✓ Associate memberships with users and client applications.
    - ✓ Add the `User` and `Administrator` Membership Levels.
    - ✓ Enforce one membership per user and client application.

  - ✓ Create the Application Role persistence model.
    - ✓ Create the `ApplicationRole` entity.
    - ✓ Associate Application Roles with client applications.
    - ✓ Enforce unique role names within each client application.

  - ✓ Create the Application Role Assignment persistence model.
    - ✓ Create the `ClientMembershipApplicationRole` entity.
    - ✓ Associate Application Roles with Client Membership.
    - ✓ Enforce unique role assignments.
    - ✓ Ensure assigned roles belong to the same client application as the membership.

  - ✓ Configure entity relationships and deletion behaviour.
    - ✓ Remove Application Role assignments when Client Membership is removed.
    - ✓ Remove related authorisation data when a user is deleted.
    - ✓ Prevent unrestricted cascading deletion of client applications.

  - ✓ Seed the initial `SoteriaAdministrator` System Role.
  - ✓ Create and apply the Entity Framework migration.
  - ✓ Verify the resulting database schema.

---

## Milestone 5.2 – Application Role Management

- ✓ Display Application Roles on Client Details.
  - ✓ Add an Application Roles section to the Client Details page.
  - ✓ Retrieve Application Roles belonging to the selected client application.
  - ✓ Display each role's Name, Display Name and Description.
  - ✓ Display an appropriate empty state when the client has no Application Roles.
  - ✓ Preserve graceful handling when the client application does not exist.
  - ✓ Verify roles belonging to other client applications are not displayed.
  - ✓ Verify existing Client Details behaviour remains unchanged.

- ✓ Create Application Roles with validation.
  - ✓ Add a Create Application Role action to Client Details.
  - ✓ Create the Application Role dialog and form.
  - ✓ Add the Application Role creation operation to the application service.
  - ✓ Associate the new role with the selected client application.
  - ✓ Require Name and Display Name.
  - ✓ Allow Description to be omitted.
  - ✓ Enforce unique role names within the selected client application.
  - ✓ Permit the same role name to be used by different client applications.
  - ✓ Validate the stable Name format used for claims and authorisation policies.
  - ✓ Display validation and persistence errors without closing the dialog.
  - ✓ Refresh the Application Roles section after successful creation.
  - ✓ Verify successful Application Role creation.
  - ✓ Verify invalid and duplicate roles are rejected.

- ✓ Edit Application Roles.
  - ✓ Add an Edit action for each Application Role.
  - ✓ Create the Application Role edit dialog and form.
  - ✓ Retrieve the selected role and verify that it belongs to the selected client application.
  - ✓ Add the Application Role update operation to the application service.
  - ✓ Display the stable Name as read-only.
  - ✓ Allow Display Name and Description to be edited.
  - ✓ Prevent the role from being moved to another client application.
  - ✓ Validate the editable fields.
  - ✓ Display validation and persistence errors without closing the dialog.
  - ✓ Refresh the Application Roles section after a successful update.
  - ✓ Verify Display Name and Description can be updated.
  - ✓ Verify the stable Name and client application association cannot be changed.

- ✓ Remove Application Roles through an explicit confirmed operation.
  - ✓ Add a Remove action for each Application Role.
  - ✓ Retrieve the number of current assignments for the selected role.
  - ✓ Display an explicit confirmation dialog before removal.
  - ✓ Include the role name and current assignment count in the warning message.
  - ✓ Warn that removing the role will also remove its existing assignments.
  - ✓ Require an explicit confirmation action before deletion.
  - ✓ Add the Application Role removal operation to the application service.
  - ✓ Verify that the role belongs to the selected client application before removal.
  - ✓ Remove associated Application Role assignments through the configured cascade behaviour.
  - ✓ Display removal errors without closing the confirmation dialog.
  - ✓ Refresh the Application Roles section after successful removal.
  - ✓ Verify removal of an unassigned Application Role.
  - ✓ Verify removal of an assigned Application Role also removes its assignments.
  - ✓ Verify cancelling the confirmation leaves the role and its assignments unchanged.

---

## Milestone 5.3 – Application Client/Role Assignment

- ✓ Display the user's Client Memberships on the User Details Permissions card.
  - ✓ Retrieve Client Memberships for the selected user.
  - ✓ Display the client application name.
  - ✓ Display the Membership Level.
  - ✓ Display assigned Application Roles.
  - ✓ Display an appropriate empty state when the user has no Client Memberships.
  - ✓ Preserve graceful handling when the selected user does not exist.
  - ✓ Verify memberships belonging to other users are not displayed.

- ✓ Assign a user to a client application.
  - ✓ Add an Assign Client action to the Permissions card.
  - ✓ Create the Client Membership dialog and form.
  - ✓ Display available client applications.
  - ✓ Exclude client applications for which the user already has a membership.
  - ✓ Allow the Membership Level to be selected.
  - ✓ Default the Membership Level to User.
  - ✓ Add the Client Membership creation operation to the application service.
  - ✓ Enforce one Client Membership per user and client application.
  - ✓ Display validation and persistence errors without closing the dialog.
  - ✓ Refresh the Permissions card after successful creation.
  - ✓ Verify duplicate memberships are rejected.

- ✓ Edit Client Memberships.
  - ✓ Open the Client Membership dialog by selecting a membership row.
  - ✓ Retrieve the selected Client Membership.
  - ✓ Verify the membership belongs to the selected user.
  - ✓ Display the client application as read-only.
  - ✓ Allow the Membership Level to be changed.
  - ✓ Retrieve available Application Roles for the client application.
  - ✓ Display Application Roles using a multi-select checklist.
  - ✓ Add and remove Application Role assignments.
  - ✓ Prevent duplicate role assignments.
  - ✓ Prevent assignment of roles belonging to another client application.
  - ✓ Display validation and persistence errors without closing the dialog.
  - ✓ Refresh the Permissions card after successful update.
  - ✓ Verify Membership Level updates are persisted.
  - ✓ Verify Application Role assignments are persisted.

- ✓ Remove Client Memberships through an explicit confirmed operation.
  - ✓ Add a Remove action to the Client Membership dialog.
  - ✓ Display an explicit confirmation dialog before removal.
  - ✓ Include the client application name in the warning message.
  - ✓ Warn that removing the Client Membership will also remove all assigned Application Roles.
  - ✓ Require explicit confirmation before deletion.
  - ✓ Add the Client Membership removal operation to the application service.
  - ✓ Remove associated Application Role assignments through the configured cascade behaviour.
  - ✓ Display removal errors without closing the confirmation dialog.
  - ✓ Refresh the Permissions card after successful removal.
  - ✓ Verify removing a membership removes its Application Role assignments.
  - ✓ Verify cancelling the confirmation leaves the membership unchanged.

---

## Milestone 5.4 – Claim Issuance

- ✓ Issue Application Role claims.
  - ✓ Issue Application Role names as standard role claims.
  - ✓ Issue only roles assigned through the Client Membership for the requesting client.
  - ✓ Preserve existing identity-oriented claims.
  - ✓ Configure claim destinations for ID and access tokens.

- ✓ Configure named authorisation policies in the reference applications.
  - ✓ Define named policies that map to Application Role names.
  - ✓ Configure the reference web application to use policy-based authorisation.
  - ✓ Demonstrate UI authorisation using issued role claims.
  - ✓ Configure the Reference API to use the same named policies.
  - ✓ Verify end-to-end authorisation using Application Role claims.

---

## Milestone 5.5 – System Administration Bootstrap

- ✓ Bootstrap the initial Soteria Administrator.
  - ✓ Define the stable `SoteriaAdministrator` System Role identifier.
  - ✓ Continue seeding the `SoteriaAdministrator` System Role.
  - ✓ Add configuration for the initial administrator email address.
  - ✓ Create an idempotent startup initializer.
  - ✓ Resolve an existing Identity user by configured email address.
  - ✓ Assign `SoteriaAdministrator` through `UserSystemRole`.
  - ✓ Skip bootstrap when a System Administrator already exists.
  - ✓ Fail clearly when the configured bootstrap user cannot be found.
  - ✓ Keep passwords and user credentials outside migrations and source control.
  - ✓ Verify the initial administrator assignment is created.
  - ✓ Verify repeated startups do not create duplicate assignments.
  - ✓ Verify bootstrap is skipped once a System Administrator exists.

- ✓ Display Soteria Administrator status on User Details.
  - ✓ Determine whether the selected user has the `SoteriaAdministrator` System Role.
  - ✓ Add administrator status to the User Details model.
  - ✓ Display a `Soteria Admin` status chip in the User Details card header.
  - ✓ Display no administrator indicator for users without the assignment.
  - ✓ Preserve the existing Client Membership permissions display.
  - ✓ Preserve graceful handling when the selected user does not exist.
  - ✓ Verify the bootstrapped System Administrator is displayed correctly.

  - ✓ Add a Soteria Administrator switch to the Edit User dialog.
  - ✓ Retrieve the current Soteria Administrator assignment.
  - ✓ Initialise the switch from the persisted assignment.
  - ✓ Allow Soteria Administrator status to be enabled and disabled.
  - ✓ Persist Soteria Administrator assignments through the User service.
  - ✓ Preserve existing account unlock behaviour.
  - ✓ Save lockout and Soteria Administrator changes together.
  - ✓ Prevent duplicate Soteria Administrator assignments.
  - ✓ Verify the selected user exists before saving.
  - ✓ Display validation and persistence errors without closing the dialog.
  - ✓ Refresh the User Details page after successful changes.
  - ✓ Verify Soteria Administrator assignments are persisted.
  - ✓ Verify Soteria Administrator assignments can be removed.
  - ✓ Verify duplicate assignments are prevented.
  - ✓ Verify cancelling leaves Soteria Administrator status unchanged.

- ✓ Introduce Soteria Administrator action authorisation.
  - ✓ Add the `SoteriaAdministrator` authorisation policy.
  - ✓ Add a dedicated authorisation requirement and handler.
  - ✓ Resolve System Role authorisation from persisted assignments.
  - ✓ Introduce a reusable current-user authorisation context.
  - ✓ Protect the Create Client action in the UI.
  - ✓ Protect client creation within the application service.
  - ✓ Protect Soteria Administrator assignment management in the UI.
  - ✓ Protect Soteria Administrator assignment changes within the application service.
  - ✓ Preserve account unlock behaviour for users without the System Role.
  - ✓ Prevent unauthorised requests that bypass UI visibility.
  - ✓ Verify Soteria Administrators can use the protected actions.
  - ✓ Verify non-administrators cannot use the protected actions.

- ✓ Implement first-run Soteria setup.
  - ✓ Allow startup when no Identity users or Soteria Administrators exist.
  - ✓ Preserve optional configuration-driven bootstrap for development.
  - ✓ Display a one-time "Register Soteria Admin" navigation option when bootstrap registration is required.
  - ✓ Restrict bootstrap registration to the first Soteria Administrator.
  - ✓ Automatically assign the first registered user the persisted `SoteriaAdministrator` System Role.
  - ✓ Disable bootstrap registration once a Soteria Administrator exists.
  - ✓ Protect against concurrent bootstrap registration attempts.
  - ✓ Verify a clean database can be initialised.
  - ✓ Verify bootstrap registration cannot be repeated.

---

## Milestone 5.6 – Delegated Client Administration

- ✓ Establish delegated administration scope.
  - ✓ Determine whether the current user is a Client Administrator.
  - ✓ Resolve the client applications administered by the current user.
  - ✓ Extend the current-user authorisation context with delegated administration information.
  - ✓ Add a reusable delegated administration authorisation policy.
  - ✓ Display the Administration navigation for Soteria Administrators and Client Administrators.
  - ✓ Restrict Administration pages from direct access by Client Users.
  - ✓ Add an Administration authorisation policy permitting Soteria Administrators and users with at least one Administrator-level Client Membership, and apply it to the Client Applications and Users pages.
  - ✓ Verify Soteria Administrators retain unrestricted administration access.
  - ✓ Verify Client Users cannot access administration features.

- ✓ Scope client administration.
  - ✓ Display only administered client applications in the client listing.
  - ✓ Prevent access to client applications outside the administrator's scope.
  - ✓ Permit editing administered client applications.
  - ✓ Permit enabling and disabling administered client applications.
  - ✓ Permit Application Role management for administered client applications.
  - ✓ Preserve Create Client as a Soteria Administrator-only action.
  - ✓ Apply delegated administration authorisation to client operations.
  - ✓ Prevent unauthorised client and Application Role operations that bypass UI visibility.
  - ✓ Verify delegated client administration is limited to administered client applications.

- ✓ Scope user administration.
  - ✓ Display only users associated with administered client applications.
  - ✓ Restrict user discovery to users associated with administered client applications.
  - ✓ Permit access to the basic User Details of a known user.
  - ✓ Prevent disclosure of Client Memberships belonging to unrelated client applications.
  - ✓ Display only Client Memberships belonging to administered client applications.
  - ✓ Restrict Client Membership creation, editing and removal to administered client applications.
  - ✓ Restrict Application Role assignment to administered client applications.
  - ✓ Preserve Soteria Administrator assignment as a Soteria Administrator-only action.
  - ✓ Preserve user self-service account management for all authenticated users.
  - ✓ Restrict Client Membership operations to administered clients.
  - ✓ Permit delegated Membership Level changes.
  - ✓ Permit appointment and revocation of Client Administrators.
  - ✓ Prevent removal or demotion of the final Client Administrator from an active client application.
  - ✓ Verify delegated administrators cannot modify unrelated client memberships.

- ✓ Enforce delegated administration within application services.
  - ✓ Apply delegated administration authorisation to client operations.
  - ✓ Apply delegated administration authorisation to user and membership operations.
  - ✓ Prevent unauthorised requests that bypass UI visibility.
  - ✓ Verify delegated administration rules are enforced consistently by application services.

---

## Milestone 5.7 – OpenID Connect Authorisation Enforcement

- ✓ Create reusable OpenId authorisation context.
  - ✓ Create a reusable `IOpenIdAuthorizationContext` service.
  - ✓ Resolve the requesting client application.
  - ✓ Resolve the authenticated Identity user.
  - ✓ Resolve the user's `ClientMembership` for the requesting client.
  - ✓ Resolve assigned `ApplicationRole` names.
  - ✓ Return a single immutable OpenId authorisation context.
  - ✓ Cache the resolved context for the lifetime of the request.
  - ✓ Define consistent resolution failure states.
  - ✓ Verify only roles belonging to the resolved `ClientMembership` are returned.

- ✓ Extract OpenId principal creation.
  - ✓ Create a reusable `IOpenIdPrincipalFactory`.
  - ✓ Build principals from the resolved authorisation context.
  - ✓ Preserve existing identity claim issuance.
  - ✓ Preserve existing Application Role claim issuance.
  - ✓ Preserve existing scope-sensitive claim destinations.
  - ✓ Preserve existing resource resolution.
  - ✓ Replace inline principal construction within the authorisation endpoint.

- ✓ Enforce Client Membership during authorisation requests.
  - ✓ Consume the shared OpenId authorisation context.
  - ✓ Reject requests when the client cannot be resolved.
  - ✓ Reject requests when the authenticated user cannot be resolved.
  - ✓ Reject requests when no matching `ClientMembership` exists.
  - ✓ Preserve existing consent behaviour.
  - ✓ Preserve existing token lifetime behaviour.
  - ✓ Verify successful authorisation for valid client memberships.

- ✓ Enforce Client Membership during token redemption.
  - ✓ Consume the shared OpenId authorisation context during authorisation-code redemption.
  - ✓ Consume the shared OpenId authorisation context during refresh-token redemption.
  - ✓ Reject redemption when the client or membership is no longer valid.
  - ✓ Preserve rolling refresh-token behaviour.
  - ✓ Preserve existing token lifetime behaviour.
  - ✓ Verify revoked memberships immediately prevent further token issuance.

---

# Phase 6 – Deployment

## Milestone 6.1 – Deployment Baseline

- ✓ Establish the deployment baseline.
  - ✓ Confirm the deployment scope.
  - ✓ Confirm the target hosting environment.
  - ✓ Confirm the canonical deployment URL.
  - ✓ Record deployment assumptions and constraints.

- ✓ Establish that no hidden configuration exists.
  - ✓ Review all application configuration sources.
  - ✓ Identify configuration required outside source control.
  - ✓ Identify development-only configuration.
  - ✓ Produce a complete deployment configuration inventory.

- ✓ Establish production-readiness gaps.
  - ✓ Review startup behaviour outside Development.
  - ✓ Review credential management.
  - ✓ Review Data Protection.
  - ✓ Review startup initialisers.
  - ✓ Produce the production-readiness action list.

---

## Milestone 6.2 – Production Runtime

- ✓ Configure OpenIddict production credentials.
  - ✓ Define the production signing credential strategy.
  - ✓ Define the production encryption credential strategy.
  - ✓ Register production signing credentials.
  - ✓ Register production encryption credentials.
  - ✓ Separate development and production credential registration.
  - ✓ Prevent development credentials being used outside Development.
  - ✓ Verify token signing.
  - ✓ Verify token encryption.
  - ✓ Verify application startup using production credentials.

- ✓ Configure persistent Data Protection.
  - ✓ Define the Data Protection persistence strategy.
  - ✓ Define the Data Protection storage location.
  - ✓ Configure persistent key storage.
  - ✓ Configure key protection.
  - ✓ Verify authentication cookies survive application restart.
  - ✓ Document key recovery expectations.

- Implement startup validation.
  - ✓ Validate required application configuration.
  - ✓ Validate deployment credentials.
  - ✓ Validate deployment directories.
  - Validate required secrets.
  - ✓ Produce clear startup failures.
  - ✓ Verify invalid deployments fail with actionable diagnostics

---

## Milestone 6.3 – Production Services

- Review startup initialisation.
  - Separate development-only startup behaviour.
  - Review OpenIddict initialisation.
  - Prevent Reference Web Application initialisation outside Development.
  - Prevent Reference API initialisation outside Development.
  - Review administrator bootstrap.
  - Verify startup remains idempotent.
  - Verify startup behaviour.

- Configure production logging.
  - Define logging providers.
  - Configure production log levels.
  - Prevent secret disclosure.
  - Define log retention.
  - Verify production logging.

- Configure production email.
  - Define deployed email support.
  - Define production email configuration.
  - Replace the Development email sender.
  - Verify account confirmation.
  - Verify password reset.
  - Verify Identity workflows.

---

## Milestone 6.4 – Deployment Architecture

- ✓ Define the IIS hosting model.
  - ✓ Define the IIS site.
  - ✓ Define the application pool.
  - ✓ Define runtime settings.
  - ✓ Define application permissions.

- Define the deployment directory structure.
  - ✓ Define the application directory.
  - ✓ Define persistent data locations.
  - ✓ Define Data Protection key storage.
  - Define logging locations.

- Define hostname and HTTPS.
  - ✓ Define the hostname.
  - ✓ Define HTTPS bindings.
  - ✓ Define certificate management.
  - Define issuer configuration.

- Define the production configuration model.
  - ✓ Define supported configuration sources.
  - ✓ Define production application settings.
  - ✓ Define environment variables.
  - Define production secret storage.
  - Produce the deployment configuration template.

---

## Milestone 6.5 – Database Deployment

- Establish the first deployment database state.
  - Determine the initial deployment database.
  - Define bootstrap administrator behaviour.
  - Remove development-only data where required.
  - Produce the initial deployment checklist.

- ✓ Define SQLite deployment.
  - ✓ Define the database location.
  - ✓ Configure permissions.
  - ✓ Verify database accessibility.
  - ✓ Define integrity expectations.

- Define database migration.
  - Define the migration procedure.
  - Define migration verification.
  - Define migration failure handling.
  - Produce the migration runbook.

- Define backup and restore.
  - Define backup procedures.
  - Define restore procedures.
  - Define rollback procedures.
  - Verify backup and restore.

---

## Milestone 6.6 – Deployment Package

- Define the publication process.
  - Define the publish model.
  - Define the publish procedure.
  - Define deployment prerequisites.
  - Verify publish output.

- Create the deployment package.
  - Define package contents.
  - Exclude development artefacts.
  - Include deployment templates.
  - Include deployment documentation.
  - Record package version.

---

## Milestone 6.7 – IIS Deployment

- ✓ Prepare the deployment host.
  - ✓ Install prerequisites.
  - ✓ Configure IIS.
  - ✓ Configure directories.
  - ✓ Configure HTTPS.

- ✓ Configure the IIS application.
  - ✓ Create the application pool.
  - ✓ Create the IIS site.
  - ✓ Configure bindings.
  - ✓ Configure application settings.

- Deploy the database.
  - Backup the existing database.
  - Deploy the production database.
  - ✓ Apply migrations.
  - ✓ Verify database deployment.

- ✓ Deploy the application.
  - ✓ Publish the release build.
  - ✓ Deploy the application files.
  - ✓ Configure production settings.
  - ✓ Verify application startup.

---

## Milestone 6.8 – Deployment Verification

- ✓ Verify platform deployment.
  - ✓ Verify HTTPS.
  - ✓ Verify issuer configuration.
  - ✓ Verify startup.
  - ✓ Verify persistent storage.

- ✓ Verify Identity functionality.
  - ✓ Verify authentication.
  - ✓ Verify administrator access.
  - ✓ Verify account management.
  - ✓ Verify application restart.

- Verify OpenIddict functionality.
  - Verify discovery metadata.
  - Verify token issuance.
  - Verify authorisation.
  - Verify token validation.

- Verify operational readiness.
  - Verify backups.
  - Verify credential persistence.
  - ✓ Verify Data Protection persistence.
  - Verify failure handling.
  - Record known limitations.

---

## Milestone 6.9 – Operational Documentation

- Produce the deployment guide.
  - Verify deployment architecture.
  - Verify deployment prerequisites.
  - Verify deployment configuration.
  - Verify deployment verification procedures.

- Produce the deployment runbook.
  - Define routine deployment.
  - Define upgrade procedures.
  - Define rollback procedures.
  - Verify deployment procedures.

- Produce the operations guide.
  - Define routine health checks.
  - Define monitoring.
  - Define certificate maintenance.
  - Define database maintenance.

- Produce the recovery guide.
  - Define deployment recovery.
  - Define database recovery.
  - Define credential recovery.
  - Verify recovery procedures.

- Review and finalise deployment documentation.
  - Verify deployment documentation.
  - Verify operational documentation.
  - Verify recovery documentation.

