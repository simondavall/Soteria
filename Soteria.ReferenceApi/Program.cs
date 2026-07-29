using System.Security.Claims;
using DotNetEnv;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation.AspNetCore;

Env.NoClobber().TraversePath().Load();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

var authority = builder.Configuration["Authentication:Authority"]
                ?? throw new InvalidOperationException(
                    "The Authentication:Authority configuration value is required.");

var encryptionKey = builder.Configuration["OpenIddict:EncryptionKey"]
                    ?? throw new InvalidOperationException(
                        "The OpenIddict:EncryptionKey configuration value is required.");

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
        options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String(encryptionKey)));

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