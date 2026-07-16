This document records significant architectural decisions made during the lifetime of the project together with the reasoning behind them. It serves as a historical record to help future developers understand why important changes were made and to avoid revisiting previously resolved discussions.

2026-07-15

Decision:

Phase 2 will prove both OpenID Connect authentication and OAuth-protected API access.

Soteria will authenticate users through ASP.NET Core Identity and use OpenIddict to issue:

- ID tokens to a server-side reference web application.
- Signed JWT access tokens intended for a distinct reference API resource.
- Refresh tokens so the reference application can renew API access without requiring the user to authenticate again whenever an access token expires.

The reference web application will call the reference API from server-side code. The initial reference client will use implicit consent and one explicit API scope. Tokens will initially contain only the claims required for the reference workflow.

Reason:

Authenticating the reference web application alone would not prove the complete architecture required by Soteria. The intended system must also allow consuming applications to call protected APIs using tokens issued by Soteria.

Using a server-side reference client keeps access tokens out of browser storage and reduces the initial browser-security and CORS surface.

A distinct API audience ensures that access tokens are issued for and accepted by the intended resource server rather than being treated as general-purpose credentials.

Starting with one scope, minimal claims and implicit consent keeps the first implementation explicit and narrow while deferring richer permissions, claims and consent policy until client application and access management are introduced.

2026-07-16

Decision:

Soteria will use Guid primary keys for ASP.NET Core Identity users and roles.

The change will be made before OpenIddict is integrated with Entity Framework Core so that both Identity and OpenIddict use a consistent Guid key model from the beginning.

The existing development database and migration history may be reset rather than supporting an in-place string-to-Guid data conversion, provided no existing database or development data must be preserved.

Reason:

Using Guid identifiers avoids retaining the ASP.NET Core Identity template's default string key type as a long-term persistence decision.

Making the change before OpenIddict persistence is introduced avoids a later migration involving both Identity and OpenIddict tables and ensures that the initial OpenIddict schema uses the intended key type.

The project is still in early development, and the current database contains no production data. Resetting the disposable development schema keeps the migration history clear and avoids introducing a complex SQLite table-reconstruction migration solely to preserve temporary development data.

2026-07-16

Decision:

Soteria will use OpenIddict-generated development X.509 certificates for its local development signing and encryption credentials.

Signing and encryption will use separate certificates. OpenIddict will store and reuse the certificates through the certificate store of the development user account running Soteria.

Development credentials will only be registered when the host environment is Development. Soteria will not use ephemeral credentials as a fallback outside Development and will not reuse the ASP.NET Core HTTPS development certificate for OpenIddict.

Non-development environments will require explicitly configured signing and encryption credentials.

The production credential strategy, including secure storage, provisioning, rotation, renewal and hosting-identity access, will be defined when the production hosting model is known. IIS-specific certificate access will be reviewed when IIS hosting becomes current work.

Reason:

Persistent development certificates allow authorization codes, tokens and other protected protocol artefacts to remain usable across application restarts while avoiding certificate files and private-key passwords in the repository.

Separate signing and encryption certificates preserve the distinction between the two security purposes and align the development model with the expected production responsibilities.

Restricting the development certificates to the Development environment prevents them from becoming an accidental production configuration. Deferring the production implementation avoids designing certificate deployment and rotation before the hosting environment and operational requirements are known.

