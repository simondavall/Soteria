using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Soteria.Data;
using Soteria.Models;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

// ================= DATABASE =================

builder.Services.AddDbContext<ApplicationDbContext>(options => {
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict<Guid>();
});

// ================= IDENTITY =================

builder.Services
    .AddIdentity<ApplicationUser, ApplicationRole>(options => {
        options.SignIn.RequireConfirmedAccount = false;

        options.Password.RequiredLength = 10;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireDigit = true;
        options.Password.RequireNonAlphanumeric = true;

        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);

        options.User.RequireUniqueEmail = true;
        options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// ================= COOKIE CONFIG =================

builder.Services.ConfigureApplicationCookie(options => {
    options.Cookie.Name = "Soteria";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;

    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout";

    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
});

// ================= OPENIDDICT =================

builder.Services.AddOpenIddict()

    .AddCore(options => {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>()
               .ReplaceDefaultEntities<Guid>();
    })

    .AddServer(options => {
        options.SetAuthorizationEndpointUris("/connect/authorize");
        options.SetTokenEndpointUris("/connect/token");
        options.SetEndSessionEndpointUris("/connect/logout");

        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow()
               .RequireProofKeyForCodeExchange();

        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15));
        options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));

        options.DisableAccessTokenEncryption();

        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Roles
        );

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough();
    });

builder.Services.AddSingleton<IEmailSender, NoOpEmailSender>();

builder.Services.AddAuthorization();
builder.Services.AddRazorPages();
builder.Services.AddControllers();

var app = builder.Build();

if (!app.Environment.IsDevelopment()) {
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

await SeedData(app);

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseStatusCodePages();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapRazorPages();

app.Run();



// ================= SEEDING =================

static async Task SeedData(WebApplication app)
{
    using var scope = app.Services.CreateScope();

    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.MigrateAsync();

    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
    var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

    string[] roles = ["Admin", "User"];

    foreach (var role in roles) {
        if (!await roleManager.RoleExistsAsync(role)) {
            await roleManager.CreateAsync(new ApplicationRole {
                Id = Guid.NewGuid(),
                Name = role,
                NormalizedName = role.ToUpper()
            });
        }
    }

    // Client app
    if (await appManager.FindByClientIdAsync("mvc-client") == null) {
        await appManager.CreateAsync(new OpenIddictApplicationDescriptor {
            ClientId = "mvc-client",
            ClientSecret = "super-secret",
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            DisplayName = "MVC Client",
            RedirectUris = { new Uri("https://localhost:7226/signin-oidc") },
            PostLogoutRedirectUris = { new Uri("https://localhost:7226/signout-callback-oidc") },
            Permissions =
            {
          OpenIddictConstants.Permissions.Endpoints.Authorization,
          OpenIddictConstants.Permissions.Endpoints.Token,
          OpenIddictConstants.Permissions.Endpoints.EndSession,
          OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
          OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
          OpenIddictConstants.Permissions.Scopes.Profile,
          OpenIddictConstants.Permissions.Scopes.Email,
          OpenIddictConstants.Permissions.Scopes.Roles,
          OpenIddictConstants.Permissions.ResponseTypes.Code
        }
        });
    }
}

