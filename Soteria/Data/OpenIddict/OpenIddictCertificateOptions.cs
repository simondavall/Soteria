using System.ComponentModel.DataAnnotations;

namespace Soteria.Data.OpenIddict;

public sealed class OpenIddictCertificateOptions
{
    public const string SectionName = "OpenIddict:Certificates";
    [Required]
    public string SigningThumbprint { get; init; } = string.Empty;
    [Required]
    public string EncryptionThumbprint { get; init; } = string.Empty;
}