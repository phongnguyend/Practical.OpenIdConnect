using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

// Add services to the container.

services.AddControllers();

services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    //options.DefaultChallengeScheme = "OAuth";
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.AccessDeniedPath = "/Authorization/AccessDenied";
})
.AddOAuth("OAuth", options =>
{
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.AuthorizationEndpoint = "https://localhost:44350/oauth/authorize";
    options.TokenEndpoint = "https://localhost:44350/oauth/token";
    options.CallbackPath = "/signin-oauth";
    options.UsePkce = true;
    options.ClientId = "MyClientId";
    options.ClientSecret = "MyClientSecret";
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("ClassifiedAds.WebAPI");
    options.Scope.Add("offline_access");
    options.SaveTokens = true;

    options.Events.OnCreatingTicket = (ticketContext) =>
    {
        return Task.CompletedTask;
    };
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.Authority = "https://localhost:44350";
    options.ClientId = "MyClientId";
    options.ClientSecret = "MyClientSecret";
    options.ResponseType = "code";
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("ClassifiedAds.WebAPI");
    options.Scope.Add("offline_access");
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.RequireHttpsMetadata = true;
    options.ResponseMode = "query";

    options.Events.OnTicketReceived = (ticketContext) =>
    {
        return Task.CompletedTask;
    };
});

services.AddAuthorization();

builder.Services.AddHttpClient();

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

app.UseAuthorization();

app.MapControllers();

app.MapGet("/", async (HttpContext ctx) =>
{
    var user = ctx.User;

    return new
    {
        isAuthenticated = user.Identity?.IsAuthenticated ?? false,
        authenticationType = user.Identity?.AuthenticationType,
        claims = user.Claims.Select(x => new { x.Type, x.Value }),
        id_token = await ctx.GetTokenAsync("id_token"),
        access_token = await ctx.GetTokenAsync("access_token"),
        refresh_token = await ctx.GetTokenAsync("refresh_token"),
        login = "/login",
        logout = "/logout",
        logout_cookies = "/logout-cookies",
    };
});

app.MapGet("/refresh-token", async (IHttpClientFactory httpClientFactory, HttpContext ctx) =>
{
    var httpClient = httpClientFactory.CreateClient();
    var metaDataResponse = await httpClient.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
    {
        Address = "https://localhost:44350",
        Policy = { RequireHttps = true },
    });

    var refreshToken = await ctx.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);
    var response = await httpClient.RequestRefreshTokenAsync(new RefreshTokenRequest
    {
        Address = metaDataResponse.TokenEndpoint,
        ClientId = "MyClientId",
        ClientSecret = "MyClientSecret",
        RefreshToken = refreshToken,
    });

    return response;
});

app.Run();
