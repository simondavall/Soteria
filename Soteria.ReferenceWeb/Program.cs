using Soteria.ReferenceWeb.Components;
using System.Net.Http.Headers;
using DotNetEnv;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Soteria.ReferenceWeb.Components.Authentication;

Env.TraversePath().Load();

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();

var openIdConnectAuthority = builder.Configuration["Authentication:OpenIdConnect:Authority"]
                             ?? throw new InvalidOperationException(
                                 "The Authentication:OpenIdConnect:Authority configuration value is required.");

var openIdConnectClientId = builder.Configuration["Authentication:OpenIdConnect:ClientId"]
                            ?? throw new InvalidOperationException(
                                "The Authentication:OpenIdConnect:ClientId configuration value is required.");

var openIdConnectClientSecret = builder.Configuration["Authentication:OpenIdConnect:ClientSecret"]
                                ?? throw new InvalidOperationException(
                                    "The Authentication:OpenIdConnect:ClientSecret configuration value is required.");

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/AccessDenied";

        options.Events.OnRedirectToLogin = context =>
        {
            if (context.Request.Path.StartsWithSegments("/internal"))
            {
                context.Response.StatusCode =
                    StatusCodes.Status401Unauthorized;

                return Task.CompletedTask;
            }

            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };

        options.Events.OnRedirectToAccessDenied = context =>
        {
            if (context.Request.Path.StartsWithSegments("/internal"))
            {
                context.Response.StatusCode =
                    StatusCodes.Status403Forbidden;

                return Task.CompletedTask;
            }

            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };
    })
    .AddOpenIdConnect(options =>
    {
        options.Authority = openIdConnectAuthority;
        options.ClientId = openIdConnectClientId;
        options.ClientSecret = openIdConnectClientSecret;
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;
        options.SaveTokens = true;
        options.MapInboundClaims = false;
        
        options.SignedOutCallbackPath = "/signout-callback-oidc";
        options.SignedOutRedirectUri = "/";

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("offline_access");
        options.Scope.Add("reference_api");

        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = "role";
    });

builder.Services.AddHttpContextAccessor();

var referenceApiBaseUrl = builder.Configuration["ReferenceApi:BaseUrl"]
                          ?? throw new InvalidOperationException(
                              "The ReferenceApi:BaseUrl configuration value is required.");

builder.Services.AddHttpClient("ReferenceApi", client => { client.BaseAddress = new Uri(referenceApiBaseUrl); });

builder.Services.AddScoped<AccessTokenManager>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapGet("/Account/Login", (string? returnUrl) =>
{
    var redirectUri = IsLocalReturnUrl(returnUrl) ? returnUrl! : "/";
    return Results.Challenge(
        new AuthenticationProperties
        {
            RedirectUri = redirectUri
        },
        [OpenIdConnectDefaults.AuthenticationScheme]);
});

app.MapPost("/Account/Logout", () => Results.SignOut(
    new AuthenticationProperties
    {
        RedirectUri = "/"
    },
    [
        CookieAuthenticationDefaults.AuthenticationScheme,
        OpenIdConnectDefaults.AuthenticationScheme
    ]));

app.MapStaticAssets();

app.MapReferenceApiEndpoint();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
return;

static bool IsLocalReturnUrl(string? returnUrl)
{
    return !string.IsNullOrWhiteSpace(returnUrl)
           && returnUrl.StartsWith('/')
           && !returnUrl.StartsWith("//")
           && !returnUrl.StartsWith("/\\");
}