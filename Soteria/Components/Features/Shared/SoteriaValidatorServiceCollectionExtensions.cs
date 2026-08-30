using FluentValidation;

namespace Soteria.Components.Features.Shared;

internal static class SoteriaValidatorServiceCollectionExtensions
{
    public static IServiceCollection AddSoteriaValidator<TValidator, TRequest>(this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TValidator : class, IValidator<TRequest>, IMudValidator<TRequest>
        where TRequest : class
    {
        ArgumentNullException.ThrowIfNull(services);

        services.Add(new ServiceDescriptor(typeof(TValidator), typeof(TValidator), lifetime));
        services.Add(new ServiceDescriptor(typeof(IValidator<TRequest>), provider => provider.GetRequiredService<TValidator>(), lifetime));
        services.Add(new ServiceDescriptor(typeof(IMudValidator<TRequest>), provider => provider.GetRequiredService<TValidator>(), lifetime));

        return services;
    }
}