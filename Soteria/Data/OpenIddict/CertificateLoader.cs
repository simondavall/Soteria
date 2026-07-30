using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Soteria.Data.OpenIddict;

internal static class CertificateLoader
{
    public static X509Certificate2 LoadSigningCertificate(OpenIddictCertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return LoadCertificate(options.SigningThumbprint, "signing");
    }

    public static X509Certificate2 LoadEncryptionCertificate(OpenIddictCertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return LoadCertificate(options.EncryptionThumbprint, "encryption");
    }

    private static X509Certificate2 LoadCertificate(string thumbprint, string purpose)
    {
        if (string.IsNullOrWhiteSpace(thumbprint))
        {
            throw new InvalidOperationException(
                $"The OpenIddict {purpose} certificate thumbprint has not been configured.");
        }

        var normalisedThumbprint = NormaliseThumbprint(thumbprint);

        ValidateThumbprint(normalisedThumbprint, purpose);

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);

        var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, normalisedThumbprint, validOnly: false);
        if (certificates.Count == 0)
        {
            throw new InvalidOperationException(
                $"The OpenIddict {purpose} certificate '{normalisedThumbprint}' " +
                "was not found in the LocalMachine\\My certificate store.");
        }

        var certificate = certificates[0];

        ValidateCertificate(certificate, normalisedThumbprint, purpose);

        return certificate;
    }

    private static void ValidateCertificate(X509Certificate2 certificate, string thumbprint, string purpose)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(
                $"The OpenIddict {purpose} certificate '{thumbprint}' does not contain a private key.");
        }

        var utcNow = DateTime.UtcNow;

        if (certificate.NotBefore.ToUniversalTime() > utcNow)
        {
            throw new InvalidOperationException(
                $"The OpenIddict {purpose} certificate '{thumbprint}' is not yet valid.");
        }

        if (certificate.NotAfter.ToUniversalTime() <= utcNow)
        {
            throw new InvalidOperationException(
                $"The OpenIddict {purpose} certificate '{thumbprint}' has expired.");
        }

        using RSA? privateKey = certificate.GetRSAPrivateKey();

        if (privateKey is null)
        {
            throw new InvalidOperationException(
                $"The OpenIddict {purpose} certificate '{thumbprint}' is not an RSA certificate with an accessible private key.");
        }

        using RSA? publicKey = certificate.GetRSAPublicKey();

        if (publicKey is null)
        {
            throw new InvalidOperationException(
                $"The OpenIddict {purpose} certificate '{thumbprint}' is not an RSA certificate.");
        }
    }

    private static void ValidateThumbprint(string thumbprint, string purpose)
    {
        if (thumbprint.Length != 40)
        {
            throw new InvalidOperationException(
                $"The OpenIddict {purpose} certificate thumbprint '{thumbprint}' is not a valid SHA-1 thumbprint.");
        }

        foreach (var character in thumbprint)
        {
            if (!Uri.IsHexDigit(character))
            {
                throw new InvalidOperationException(
                    $"The OpenIddict {purpose} certificate thumbprint '{thumbprint}' contains invalid characters.");
            }
        }
    }

    private static string NormaliseThumbprint(string thumbprint)
    {
        return thumbprint
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Trim()
            .ToUpperInvariant();
    }
}