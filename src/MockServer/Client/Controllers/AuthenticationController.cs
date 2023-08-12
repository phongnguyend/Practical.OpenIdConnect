using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace ReverseProxy.Yarp.Controllers
{
    public class AuthenticationController : ControllerBase
    {
        [HttpGet("/login")]
        public async Task LoginAsync(string returnUrl)
        {
            if (HttpContext.User.Identity?.IsAuthenticated ?? false)
            {
                Response.Redirect("/");
            }
            else
            {
                //await HttpContext.ChallengeAsync("OAuth", new AuthenticationProperties
                //{
                //    RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
                //});

                await HttpContext.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
                {
                    RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/"
                });
            }
        }

        [HttpGet("/logout")]
        public async Task LogoutAsync()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            //await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
        }

        [HttpGet("/logout-cookies")]
        public async Task LogoutCookiesAsync()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            Response.Redirect("/");
        }
    }
}
