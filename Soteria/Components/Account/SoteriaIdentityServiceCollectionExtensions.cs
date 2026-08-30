using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Soteria.Components.Account.Email;
using Soteria.Data;

namespace Soteria.Components.Account;

internal static class SoteriaIdentityServiceCollectionExtensions
{
    public static IServiceCollection AddSoteriaIdentity(this IServiceCollection services, 
        IWebHostEnvironment environment, 
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddCascadingAuthenticationState();

        services.AddScoped<IdentityRedirectManager>();
        services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

        services.AddAuthentication(options =>
            {
                options.DefaultScheme = IdentityConstants.ApplicationScheme;
                options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            })
            .AddIdentityCookies();

        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = "Soteria.Identity";
            options.LoginPath = "/Account/Login";
            options.ReturnUrlParameter = "ReturnUrl";
        });

        services.AddIdentityCore<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = true;
                options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddEntityFrameworkStores<SoteriaDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

        if (environment.IsDevelopment())
        {
            services.AddSingleton<IEmailSender<ApplicationUser>, DevelopmentEmailSender>();
        }
        else
        {
            var emailOptions = EmailOptionsLoader.Load(configuration);

            services.AddSingleton(emailOptions);
            services.AddSingleton<IEmailSender<ApplicationUser>, EmailSender>();
        }

        return services;
    }
}