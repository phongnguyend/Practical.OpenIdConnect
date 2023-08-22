using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MockServer.Extensions;
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

var authorizeRequests = new Dictionary<string, AuthorizeRequest>();
var refreshTokens = new Dictionary<string, RefreshToken>();

app.MapGet("/account/login", (HttpContext httpContext, [FromQuery] string returnUrl) =>
{
    return Results.Text(@$"
    <form action=""/account/login?returnUrl={HttpUtility.UrlEncode(returnUrl)}"" method=""POST"">
      <label for=""username"">Username:</label>
      <input type=""text"" id=""username"" name=""username"" value=""phong@gmail.com""><br><br>
      <input type=""submit"" value=""Login"">
    </form>
    ", "text/html");
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

app.MapGet("/.well-known/openid-configuration", () =>
{
    return Results.Ok(new
    {
        issuer = "https://localhost:44350",
        jwks_uri = "https://localhost:44350/.well-known/jwks",
        authorization_endpoint = "https://localhost:44350/oauth/authorize",
        token_endpoint = "https://localhost:44350/oauth/token",
        response_types_supported = new[] { "code", "token" },
        id_token_signing_alg_values_supported = new[] { "RS256" },
        userinfo_endpoint = "https://localhost:44350/oauth/userinfo"
    });
});

app.MapGet("/.well-known/jwks", () =>
{
    var x509Cert = new X509Certificate2("Certs/classifiedads.identityserver.pfx", "password1234");

    return new
    {
        keys = new[] { x509Cert.GetRsaPublicJwk() },
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

    var returnUrl = $"{redirectUri}?code={code}&state={state}&iss={HttpUtility.UrlEncode("https://localhost:44350")}";

    return Results.Redirect($"/oauth/consent?returnUrl={HttpUtility.UrlEncode(returnUrl)}");

}).RequireAuthorization();

app.MapGet("/oauth/consent", (HttpContext httpContext, [FromQuery] string returnUrl) =>
{
    return Results.Text(@$"
    <form action=""/oauth/consent?returnUrl={HttpUtility.UrlEncode(returnUrl)}"" method=""POST"">
      <input type=""submit"" value=""Accept"">
    </form>
    ", "text/html");
});

app.MapPost("/oauth/consent", (HttpContext httpContext, [FromQuery] string returnUrl) =>
{
    return Results.Redirect(returnUrl);
});

app.MapPost("/oauth/token", (HttpRequest request) =>
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

    if (string.IsNullOrEmpty(tokenRequest.Code)
        || !authorizeRequests.ContainsKey(tokenRequest.Code)
        || string.IsNullOrEmpty(tokenRequest.CodeVerifier)
        )
    {
        return Results.BadRequest();
    }

    var authRequest = authorizeRequests[tokenRequest.Code];

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

    var accessToken = CreateToken(authClaims, DateTime.Now.AddMinutes(15), "WebAPI");
    var idToken = CreateToken(authClaims, DateTime.Now.AddMinutes(15), authRequest.ClientId);

    string? refreshToken = null;
    if (authRequest.Scope?.Split(' ')?.Contains("offline_access") ?? false)
    {
        refreshToken = Guid.NewGuid().ToString();
        refreshTokens[refreshToken] = new RefreshToken
        {
            ClientId = authRequest.ClientId,
        };
    }

    var response = new
    {
        access_token = new JwtSecurityTokenHandler().WriteToken(accessToken),
        token_type = "Bearer",
        id_token = new JwtSecurityTokenHandler().WriteToken(idToken),
        refresh_token = refreshToken,
    };

    return Results.Ok(response);
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


app.Run();

static JwtSecurityToken CreateToken(List<Claim> authClaims, DateTime expires, string audience)
{
    var token = new JwtSecurityToken(
        issuer: "https://localhost:44350",
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
    return new X509SecurityKey(new X509Certificate2("Certs/classifiedads.identityserver.pfx", "password1234"));
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
}