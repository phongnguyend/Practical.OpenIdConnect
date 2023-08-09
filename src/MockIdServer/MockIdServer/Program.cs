using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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

var dic = new Dictionary<string, AuthorizeRequest>();

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
        authorization_endpoint = "https://localhost:44350/oauth/authorize",
        token_endpoint = "https://localhost:44350/oauth/token",
        response_types_supported = new[] { "code", "token" },
        id_token_signing_alg_values_supported = new[] { "RS256" },
        userinfo_endpoint = "https://localhost:44350/oauth/userinfo"
    });
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

    var code = Guid.NewGuid().ToString();

    dic[code] = new AuthorizeRequest
    {
        ResponseType = responseType,
        ClientId = clientId,
        CodeChallenge = codeChallenge,
        CodeChallengeMethod = codeChallengeMethod,
        RedirectUri = redirectUri,
        Scope = scope,
        State = state,
        Expiry = DateTime.UtcNow.AddMinutes(10)
    };

    return Results.Redirect($"{redirectUri}?code={code}&state={state}&iss={HttpUtility.UrlEncode("https://localhost:44350")}");

}).RequireAuthorization();

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

    var authRequest = dic[tokenRequest.Code];

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
        new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToString()),
    };

    var token = CreateToken(authClaims, DateTime.Now.AddMinutes(15));

    return Results.Ok(new
    {
        access_token = new JwtSecurityTokenHandler().WriteToken(token),
        token_type = "Bearer",
        id_token = Guid.NewGuid().ToString(),
    });
});

app.MapPost("/oauth/userinfo", (HttpRequest request) =>
{

});


app.Run();

static JwtSecurityToken CreateToken(List<Claim> authClaims, DateTime expires)
{
    var token = new JwtSecurityToken(
        issuer: "https://localhost:44350",
        audience: "xxx",
        expires: expires,
        claims: authClaims,
        signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secretsecretsecretsecretsecretsecret")), SecurityAlgorithms.HmacSha256));

    return token;
}

class AuthorizeRequest
{
    public string ResponseType { get; set; }

    public string ClientId { get; set; }

    public string CodeChallenge { get; set; }

    public string CodeChallengeMethod { get; set; }

    public string RedirectUri { get; set; }

    public string Scope { get; set; }

    public string State { get; set; }

    public DateTime Expiry { get; set; }
}

public class TokenRequest
{
    public string ClientId { get; set; }

    public string ClientSecret { get; set; }

    public string GrantType { get; set; }

    public string Code { get; set; }

    public string RedirectUri { get; set; }

    public string CodeVerifier { get; set; }
}