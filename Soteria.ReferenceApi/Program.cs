using System.Security.Claims;
using DotNetEnv;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation.AspNetCore;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

if (builder.Environment.IsDevelopment())
{
    Env.NoClobber().TraversePath().Load();

    // DotNetEnv runs after the builder has loaded its initial configuration.
    // Add the resulting process environment variables to configuration.
    builder.Configuration.AddEnvironmentVariables();
}

builder.Services.AddOpenApi();

var authority = builder.Configuration["Authentication:Authority"]
                ?? throw new InvalidOperationException(
                    "The Authentication:Authority configuration value is required.");

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = "ReferenceApi.Authentication";
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Editor", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireRole("Editor");
    });

    options.AddPolicy("Auditor", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireRole("Auditor");
    });

    options.AddPolicy("EditorOrReviewer", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireRole("Editor", "Reviewer");
    });

    options.AddPolicy("DevelopmentClaims", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(_ => builder.Environment.IsDevelopment());
    });
});

builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        options.SetIssuer(authority);
        options.AddAudiences("reference_api");

        if (builder.Environment.IsDevelopment())
        {
            var encryptionKey = builder.Configuration["OpenIddict:EncryptionKey"]
                                ?? throw new InvalidOperationException(
                                    "The OpenIddict:EncryptionKey configuration value is required in Development.");

            byte[] encryptionKeyBytes;

            try
            {
                encryptionKeyBytes = Convert.FromBase64String(encryptionKey);
            }
            catch (FormatException exception)
            {
                throw new InvalidOperationException(
                    "The OpenIddict:EncryptionKey configuration value must be valid Base64.",
                    exception);
            }

            options.AddEncryptionKey(
                new SymmetricSecurityKey(encryptionKeyBytes));
        }
        else if (builder.Environment.IsProduction())
        {
            var encryptionCertificate =
                LoadProductionEncryptionCertificate(builder.Configuration);

            options.AddEncryptionCertificate(encryptionCertificate);
        }
        else
        {
            throw new InvalidOperationException(
                $"OpenIddict validation credentials are not configured for the " +
                $"'{builder.Environment.EnvironmentName}' environment.");
        }

        options.Configure(validationOptions =>
        {
            validationOptions.TokenValidationParameters.RoleClaimType = "role";
            validationOptions.TokenValidationParameters.NameClaimType = "name";
        });

        options.UseSystemNetHttp();
        options.UseAspNetCore();
    });

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/reference", () => Results.Ok(new { Message = "Reference API reachable" }))
    .RequireAuthorization()
    .WithName("GetReference");

app.MapGet("/api/editor", (ClaimsPrincipal user) => Results.Ok(new { Message = $"Reference API Editor policy satisfied for {DisplayName(user)}." }))
    .RequireAuthorization("Editor")
    .WithName("GetEditor");

app.MapGet("/api/auditor", (ClaimsPrincipal user) => Results.Ok(new { Message = $"Reference API Auditor policy satisfied for {DisplayName(user)}." }))
    .RequireAuthorization("Auditor")
    .WithName("GetAuditor");

app.MapGet("/api/review",
        (ClaimsPrincipal user) => Results.Ok(new { Message = $"Reference API Editor or Reviewer policy satisfied for {DisplayName(user)}." }))
    .RequireAuthorization("EditorOrReviewer")
    .WithName("GetReview");

app.MapGet("/api/claims", (ClaimsPrincipal user) =>
    {
        var roleClaimType = user.Identities
                                .FirstOrDefault()?
                                .RoleClaimType
                            ?? "role";

        var roles = user.Claims
            .Where(claim => claim.Type == roleClaimType)
            .Select(claim => claim.Value)
            .OrderBy(value => value)
            .ToArray();

        var remainingClaims = user.Claims
            .Where(claim => claim.Type != roleClaimType)
            .OrderBy(claim => claim.Type)
            .ThenBy(claim => claim.Value)
            .Select(claim => new
            {
                claim.Type,
                claim.Value,
                claim.ValueType,
                claim.Issuer
            })
            .ToArray();

        return Results.Ok(new
        {
            Name = user.Identity?.Name,
            Subject = user.FindFirst("sub")?.Value,
            Username = user.FindFirst("preferred_username")?.Value,
            Email = user.FindFirst("email")?.Value,
            AuthenticationType = user.Identity?.AuthenticationType,
            RoleClaimType = roleClaimType,
            Roles = roles,
            Claims = remainingClaims
        });
    })
    .RequireAuthorization("DevelopmentClaims")
    .WithName("GetClaims");

app.Run();

static string DisplayName(ClaimsPrincipal user)
{
    return user.Identity?.Name
           ?? user.FindFirst("preferred_username")?.Value
           ?? user.FindFirst("sub")?.Value
           ?? "the authenticated user";
}

static X509Certificate2 LoadProductionEncryptionCertificate(IConfiguration configuration)
{
    var configuredThumbprint = configuration["OpenIddict:EncryptionCertificateThumbprint"];

    if (string.IsNullOrWhiteSpace(configuredThumbprint))
    {
        throw new InvalidOperationException(
            "The OpenIddict:EncryptionCertificateThumbprint configuration " +
            "value is required in Production.");
    }

    var thumbprint = NormalizeCertificateThumbprint(configuredThumbprint);

    using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadOnly);

    var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
    var certificate = certificates.OfType<X509Certificate2>().SingleOrDefault();
    if (certificate is null)
    {
        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with thumbprint " +
            $"'{thumbprint}' was not found in LocalMachine\\My.");
    }

    if (!certificate.HasPrivateKey)
    {
        certificate.Dispose();

        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with thumbprint " +
            $"'{thumbprint}' does not contain an accessible private key.");
    }

    if (certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow)
    {
        certificate.Dispose();

        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with thumbprint " +
            $"'{thumbprint}' is not yet valid.");
    }

    if (certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
    {
        certificate.Dispose();

        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with thumbprint " +
            $"'{thumbprint}' has expired.");
    }

    using var rsaPrivateKey = certificate.GetRSAPrivateKey();

    if (rsaPrivateKey is null)
    {
        certificate.Dispose();

        throw new InvalidOperationException(
            $"The OpenIddict encryption certificate with thumbprint " +
            $"'{thumbprint}' does not provide an RSA private key.");
    }

    return certificate;
}

static string NormalizeCertificateThumbprint(string thumbprint)
{
    var normalized = new string(
        thumbprint
            .Where(character => !char.IsWhiteSpace(character))
            .ToArray());

    if (normalized.Length == 0 || normalized.Any(character => !Uri.IsHexDigit(character)))
    {
        throw new InvalidOperationException(
            "The OpenIddict:EncryptionCertificateThumbprint configuration " +
            "value must contain a hexadecimal certificate thumbprint.");
    }

    return normalized;
}