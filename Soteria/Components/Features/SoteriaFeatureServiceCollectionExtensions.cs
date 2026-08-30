using FluentValidation;
using Soteria.Components.Features.ClientMemberships;
using Soteria.Components.Features.ClientMemberships.Queries;
using Soteria.Components.Features.Clients;
using Soteria.Components.Features.Clients.Queries;
using Soteria.Components.Features.Shared;
using Soteria.Components.Features.Users;
using Soteria.Components.Features.Users.Queries;

namespace Soteria.Components.Features;

internal static class SoteriaFeatureServiceCollectionExtensions
{
    extension(IServiceCollection services)
    {
        public IServiceCollection AddSoteriaFeatures()
        {
            ArgumentNullException.ThrowIfNull(services);

            services.AddClientFeatures();
            services.AddUserFeatures();
            services.AddClientMembershipFeatures();
            services.AddApplicationRoleFeatures();

            return services;
        }

        private void AddClientFeatures()
        {
            services.AddScoped<IClientApplicationLookup, ClientApplicationLookup>();
            services.AddScoped<ClientService>();
            services.AddSoteriaValidator<CreateClientValidator, CreateClientRequest>(ServiceLifetime.Transient);
            services.AddSoteriaValidator<EditClientValidator, EditClientRequest>(ServiceLifetime.Transient);
        }

        private void AddUserFeatures()
        {
            services.AddScoped<IUserLookup, UserLookup>();
            services.AddScoped<UserService>();
            services.AddSoteriaValidator<CreateUserValidator, CreateUserRequest>();
            services.AddSoteriaValidator<EditUserValidator, EditUserRequest>();
        }

        private void AddClientMembershipFeatures()
        {
            services.AddScoped<IClientMembershipLookup, ClientMembershipLookup>();
            services.AddScoped<IClientMembershipService, ClientMembershipService>();
            services.AddSoteriaValidator<CreateClientMembershipValidator, CreateClientMembershipRequest>();
            services.AddSoteriaValidator<EditClientMembershipValidator, EditClientMembershipRequest>();
            services.AddScoped<RemoveClientMembershipValidator>();
            services.AddScoped<IValidator<RemoveClientMembershipRequest>>(provider => provider.GetRequiredService<RemoveClientMembershipValidator>());
        }

        private void AddApplicationRoleFeatures()
        {
            services.AddScoped<IApplicationRoleLookup, ApplicationRoleLookup>();
            services.AddSoteriaValidator<CreateApplicationRoleValidator, CreateApplicationRoleRequest>(ServiceLifetime.Transient);
            services.AddSoteriaValidator<EditApplicationRoleValidator, EditApplicationRoleRequest>(ServiceLifetime.Transient);
        }
    }
}