using CryptographyHelper.Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MockServer.Extensions;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication()
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

var authorizeRequests = new ConcurrentDictionary<string, AuthorizeRequest>();
var refreshTokens = new ConcurrentDictionary<string, RefreshToken>();

app.MapGet("/account/login", (HttpContext httpContext, [FromQuery] string returnUrl) =>
{
    var html = $"""
    <form action="/account/login?returnUrl={HttpUtility.UrlEncode(returnUrl)}" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" value="phong@gmail.com"><br><br>
        <input type="submit" value="Login">
    </form>
    """;
    return Results.Text(html, "text/html");
});

app.MapPost("/account/login", async (HttpContext httpContext, [FromQuery] string returnUrl) =>
{
    // https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie?view=aspnetcore-7.0

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, "Phong"),
        new Claim("FullName", "Phong Nguyen"),
        new Claim(ClaimTypes.Role, "Administrator"),
    };

    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
    var authProperties = new AuthenticationProperties
    {
    };

    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal, authProperties);
    return Results.Redirect(returnUrl);
});

var issuer = "https://localhost:7248";

app.MapGet("/.well-known/openid-configuration", () =>
{
    return Results.Ok(new
    {
        issuer = $"{issuer}",
        jwks_uri = $"{issuer}/.well-known/jwks",
        authorization_endpoint = $"{issuer}/oauth/authorize",
        token_endpoint = $"{issuer}/oauth/token",
        response_types_supported = new[] { "code", "token" },
        id_token_signing_alg_values_supported = new[] { "RS256" },
        userinfo_endpoint = $"{issuer}/oauth/userinfo"
    });
});

app.MapGet("/.well-known/jwks", () =>
{
    var x509Cert = GetX509Certificate();
    var rsaSercutiryKey = new RsaSecurityKey(x509Cert.GetRSAPublicKey());
    var parameters = rsaSercutiryKey.Rsa.ExportParameters(false);

    return new
    {
        keys = new[]
        {
            //JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaSercutiryKey),
            new
            {
                kty = "RSA",
                use = "sig",
                kid = x509Cert.Thumbprint,
                n = Base64UrlEncoder.Encode(parameters.Modulus),
                e = Base64UrlEncoder.Encode(parameters.Exponent)
            }
        },
    };

});

app.MapGet("/oauth/authorize", (HttpRequest request) =>
{
    request.Query.TryGetValue("response_type", out var responseType);
    request.Query.TryGetValue("client_id", out var clientId);
    request.Query.TryGetValue("code_challenge", out var codeChallenge);
    request.Query.TryGetValue("code_challenge_method", out var codeChallengeMethod);
    request.Query.TryGetValue("redirect_uri", out var redirectUri);
    request.Query.TryGetValue("scope", out var scope);
    request.Query.TryGetValue("state", out var state);
    request.Query.TryGetValue("nonce", out var nonce);

    var code = Guid.NewGuid().ToString();

    authorizeRequests[code] = new AuthorizeRequest
    {
        ResponseType = responseType,
        ClientId = clientId,
        CodeChallenge = codeChallenge,
        CodeChallengeMethod = codeChallengeMethod,
        RedirectUri = redirectUri,
        Scope = scope,
        State = state,
        Nonce = nonce,
        Expiry = DateTime.UtcNow.AddMinutes(10)
    };

    var returnUrl = $"{redirectUri}?code={code}&state={state}&iss={HttpUtility.UrlEncode(issuer)}";

    return Results.Redirect($"/oauth/consent?returnUrl={HttpUtility.UrlEncode(returnUrl)}");

}).RequireAuthorization();

app.MapGet("/oauth/consent", (HttpContext httpContext, [FromQuery] string returnUrl) =>
{
    var html = $"""
    <form action="/oauth/consent?returnUrl={HttpUtility.UrlEncode(returnUrl)}" method="POST">
        <input type="submit" value="Accept">
    </form>
    """;
    return Results.Text(html, "text/html");
});

app.MapPost("/oauth/consent", (HttpContext httpContext, [FromQuery] string returnUrl) =>
{
    return Results.Redirect(returnUrl);
});

app.MapPost("/oauth/token", (HttpRequest request) =>
{
    var grantType = request.Form["grant_type"];

    if (grantType == "authorization_code")
    {
        var tokenRequest = new TokenRequest
        {
            ClientId = request.Form["client_id"],
            ClientSecret = request.Form["client_secret"],
            GrantType = request.Form["grant_type"],
            Code = request.Form["code"],
            CodeVerifier = request.Form["code_verifier"],
            RedirectUri = request.Form["redirect_uri"],
        };

        if (string.IsNullOrEmpty(tokenRequest.Code) || string.IsNullOrEmpty(tokenRequest.CodeVerifier)
            || !authorizeRequests.TryGetValue(tokenRequest.Code, out var authRequest))
        {
            return Results.BadRequest();
        }

        // verify code
        using var sha256 = SHA256.Create();
        if (authRequest.CodeChallenge != Base64UrlEncoder.Encode(sha256.ComputeHash(Encoding.ASCII.GetBytes(tokenRequest.CodeVerifier))))
        {
            return Results.BadRequest();
        }

        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "phong@gmail.com"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.Now).ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, "phong@gmail.com"),
        };

        if (!string.IsNullOrEmpty(authRequest.Nonce))
        {
            authClaims.Add(new Claim(JwtRegisteredClaimNames.Nonce, authRequest.Nonce));
        }

        var expiresIn = TimeSpan.FromMinutes(15).TotalSeconds;

        var accessToken = CreateToken(authClaims, DateTime.Now.AddSeconds(expiresIn), issuer, "WebAPI");
        var idToken = CreateToken(authClaims, DateTime.Now.AddSeconds(expiresIn), issuer, authRequest.ClientId!);

        string? refreshToken = null;
        if (authRequest.Scope?.Split(' ')?.Contains("offline_access") ?? false)
        {
            refreshToken = Guid.NewGuid().ToString();
            refreshTokens[refreshToken] = new RefreshToken
            {
                ClientId = authRequest.ClientId,
                Sub = "phong@gmail.com",
                Audience = "WebAPI",
                Scope = authRequest.Scope,
                ExpirationDateTime = DateTimeOffset.Now.AddDays(1),
                CreatedDateTime = DateTimeOffset.Now
            };
        }

        var response = new
        {
            access_token = new JwtSecurityTokenHandler().WriteToken(accessToken),
            token_type = "Bearer",
            expires_in = expiresIn - 10,
            id_token = new JwtSecurityTokenHandler().WriteToken(idToken),
            refresh_token = refreshToken,
        };

        return Results.Ok(response);
    }
    else if (grantType == "client_credentials")
    {
        string? clientId;
        string? clientSecret;
        if (!request.TryGetBasicCredentials(out clientId, out clientSecret))
        {
            clientId = request.Form["client_id"];
            clientSecret = request.Form["client_secret"];
        }

        var audience = request.Form["audience"];

        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "My Client Name"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.Now).ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, clientId!),
        };

        var expiresIn = TimeSpan.FromMinutes(15).TotalSeconds;

        var accessToken = CreateToken(authClaims, DateTime.Now.AddSeconds(expiresIn), issuer, audience!);

        var response = new
        {
            access_token = new JwtSecurityTokenHandler().WriteToken(accessToken),
            token_type = "Bearer",
            expires_in = expiresIn - 10,
        };

        return Results.Ok(response);
    }
    else if (grantType == "password")
    {
        string? clientId;
        string? clientSecret;
        if (!request.TryGetBasicCredentials(out clientId, out clientSecret))
        {
            clientId = request.Form["client_id"];
            clientSecret = request.Form["client_secret"];
        }

        var username = request.Form["username"];
        var password = request.Form["password"];
        var audience = request.Form["audience"];
        var scope = request.Form["scope"].ToString();

        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "phong@gmail.com"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.Now).ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, "phong@gmail.com"),
        };

        var expiresIn = TimeSpan.FromMinutes(15).TotalSeconds;

        var accessToken = CreateToken(authClaims, DateTime.Now.AddSeconds(expiresIn), issuer, audience!);

        string? refreshToken = null;
        if (scope?.Split(' ')?.Contains("offline_access") ?? false)
        {
            refreshToken = Guid.NewGuid().ToString();
            refreshTokens[refreshToken] = new RefreshToken
            {
                ClientId = clientId,
                Sub = "phong@gmail.com",
                Audience = audience,
                Scope = scope,
                ExpirationDateTime = DateTimeOffset.Now.AddDays(1),
                CreatedDateTime = DateTimeOffset.Now
            };
        }

        var response = new
        {
            access_token = new JwtSecurityTokenHandler().WriteToken(accessToken),
            token_type = "Bearer",
            expires_in = expiresIn - 10,
            refresh_token = refreshToken,
        };

        return Results.Ok(response);
    }
    else if (grantType == "refresh_token")
    {
        var refreshToken = request.Form["refresh_token"];
        string? clientId;
        string? clientSecret;
        if (!request.TryGetBasicCredentials(out clientId, out clientSecret))
        {
            clientId = request.Form["client_id"];
            clientSecret = request.Form["client_secret"];
        }

        if (string.IsNullOrEmpty(refreshToken) || !refreshTokens.TryGetValue(refreshToken!, out var refreshTokenRecord))
        {
            return Results.BadRequest(new
            {
                error = "invalid_refresh_token"
            });
        }

        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "phong@gmail.com"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.Now).ToString()),
            new Claim(JwtRegisteredClaimNames.Sub, "phong@gmail.com"),
        };

        var expiresIn = TimeSpan.FromMinutes(15).TotalSeconds;

        var accessToken = CreateToken(authClaims, DateTime.Now.AddSeconds(expiresIn), issuer, refreshTokenRecord.Audience!);

        string? newRefreshToken = Guid.NewGuid().ToString();

        refreshTokens[newRefreshToken] = new RefreshToken
        {
            ClientId = refreshTokenRecord.ClientId,
            Sub = refreshTokenRecord.Sub,
            Audience = refreshTokenRecord.Audience!,
            Scope = refreshTokenRecord.Scope,
            ExpirationDateTime = DateTimeOffset.Now.AddDays(1),
            CreatedDateTime = DateTimeOffset.Now
        };

        refreshTokens.TryRemove(refreshToken!, out _);

        var response = new
        {
            access_token = new JwtSecurityTokenHandler().WriteToken(accessToken),
            token_type = "Bearer",
            expires_in = expiresIn - 10,
            refresh_token = newRefreshToken,
        };

        return Results.Ok(response);
    }

    return Results.BadRequest(new
    {
        error = "unsupported_grant_type"
    });
});

app.MapGet("/oauth/userinfo", (HttpRequest request) =>
{
    var response = new Dictionary<string, object>
    {
        {"sub", "phong@gmail.com"},
        {"name", "Phong Nguyen" },
        {"email", "phong @gmail.com"}
    };

    return Results.Ok(response);
});

app.MapPost("/oauth/userinfo", (HttpRequest request) =>
{
    var response = new Dictionary<string, object>
    {
        {"sub", "phong@gmail.com"},
        {"name", "Phong Nguyen" },
        {"email", "phong @gmail.com"}
    };

    return Results.Ok(response);
});

app.MapGet("/internal/database", (HttpRequest request) =>
{
    return Results.Ok(new
    {
        authorizeRequests,
        refreshTokens
    });
});

app.Run();

static JwtSecurityToken CreateToken(List<Claim> authClaims, DateTime expires, string issuer, string audience)
{
    var token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        expires: expires,
        claims: authClaims,
        signingCredentials: GetSigningCredentials());

    return token;
}

static SigningCredentials GetSigningCredentials()
{
    return new SigningCredentials(GetSigningKey(), SecurityAlgorithms.RsaSha256);
}

static SecurityKey GetSigningKey()
{
    return new X509SecurityKey(GetX509Certificate());
}

static X509Certificate2 GetX509Certificate()
{
    return CertificateFile.Find("Certs/Practical.OpenIdConnect.pfx", "password1234", X509KeyStorageFlags.EphemeralKeySet);
}

class AuthorizeRequest
{
    public string? ResponseType { get; set; }

    public string? ClientId { get; set; }

    public string? CodeChallenge { get; set; }

    public string? CodeChallengeMethod { get; set; }

    public string? RedirectUri { get; set; }

    public string? Scope { get; set; }

    public string? State { get; set; }

    public string? Nonce { get; set; }

    public DateTime Expiry { get; set; }
}

public class TokenRequest
{
    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    public string? GrantType { get; set; }

    public string? Code { get; set; }

    public string? RedirectUri { get; set; }

    public string? CodeVerifier { get; set; }
}

public class RefreshToken
{
    public string? ClientId { get; set; }

    public required string Sub { get; set; }

    public string? Audience { get; set; }

    public string? Scope { get; set; }

    public DateTimeOffset ExpirationDateTime { get; set; }

    public DateTimeOffset CreatedDateTime { get; set; }
}