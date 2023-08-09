using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

// Add services to the container.

services.AddControllers();

services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "OAuth";
    //options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
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
    options.CallbackPath = "/signin-oidc";
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

    options.Events.OnTicketReceived = (ticketContext) =>
    {
        return Task.CompletedTask;
    };
});

services.AddAuthorization();

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

app.MapGet("/", (HttpContext ctx) =>
{
    return ctx.User;
});

app.Run();
