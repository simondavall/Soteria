using System.Security.Cryptography.X509Certificates;

namespace Soteria.Data.OpenIddict;

internal static class CertificateLoader
{
    public static X509Certificate2 LoadSigningCertificate(OpenIddictCertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return LoadCertificate(options.SigningThumbprint);
    }

    public static X509Certificate2 LoadEncryptionCertificate(OpenIddictCertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return LoadCertificate(options.EncryptionThumbprint);
    }

    private static X509Certificate2 LoadCertificate(string thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint))
        {
            throw new InvalidOperationException(
                "The OpenIddict certificate thumbprint has not been configured.");
        }

        var normalisedThumbprint = NormaliseThumbprint(thumbprint);

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

        store.Open(OpenFlags.ReadOnly);

        var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, normalisedThumbprint, validOnly: false);
        if (certificates.Count == 0)
        {
            throw new InvalidOperationException(
                $"No certificate with thumbprint '{normalisedThumbprint}' " +
                "was found in the LocalMachine\\My certificate store.");
        }

        return certificates[0];
    }

    private static string NormaliseThumbprint(string thumbprint)
    {
        return thumbprint
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Trim()
            .ToUpperInvariant();
    }
}