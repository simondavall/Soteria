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

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme =
        OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme =
        OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

builder.Services.AddAuthorization();

builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        options.SetIssuer(authority);
        options.AddAudiences("reference_api");

        options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String(encryptionKey)));

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

app.MapGet("/api/reference", () =>
        Results.Ok(new
        {
            Message = "Reference API reachable"
        }))
    .RequireAuthorization()
    .WithName("GetReference");

app.Run();