using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace MockServer.Extensions
{
    public static class X509CertificateExtension
    {
        public static JsonWebKey GetRsaPublicJwk(this X509Certificate2 certificate, string use = default)
        {
            if (certificate == null)
            {
                return null;
            }

            var key = new JsonWebKey
            {
                X5c = { Convert.ToBase64String(certificate.RawData) },
                Kty = JsonWebAlgorithmsKeyTypes.RSA,
                X5t = certificate.Thumbprint
            };

            var document = new XmlDocument();
            document.LoadXml(certificate.PublicKey.GetRSAPublicKey()?.ToXmlString(false) ?? string.Empty);
            if (document.SelectSingleNode("/RSAKeyValue/Modulus") is { } modulus &&
                !string.IsNullOrWhiteSpace(modulus.InnerText))
            {
                key.N = Base64UrlEncoder.Encode(Convert.FromBase64String(modulus.InnerText));
            }

            if (document.SelectSingleNode("/RSAKeyValue/Exponent") is { } exponent &&
                !string.IsNullOrWhiteSpace(exponent.InnerText))
            {
                key.E = Base64UrlEncoder.Encode(Convert.FromBase64String(exponent.InnerText));
            }

            if (!string.IsNullOrWhiteSpace(key.E) && !string.IsNullOrWhiteSpace(key.N))
            {
                key.Kid = $"{key.N}{key.E}".Sha512();
            }

            if (!string.IsNullOrWhiteSpace(use))
            {
                key.Use = use;
            }

            return key;
        }

        public static string Sha512(this string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }

            using var sha = SHA512.Create();
            var textData = Encoding.UTF8.GetBytes(text);
            var hash = sha.ComputeHash(textData);
            return string.Concat(hash.Select(b => b.ToString("x2")));
        }
    }
}
