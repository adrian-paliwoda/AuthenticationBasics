using System.Security.Claims;
using System.Text.Encodings.Web;
using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace AuthenticationBasicsApp.AuthenticationHandlers;

public class VisitorAuthHandler : CookieAuthenticationHandler
{
    public VisitorAuthHandler(IOptionsMonitor<CookieAuthenticationOptions> options, ILoggerFactory logger,
        UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();
        if (result.Succeeded)
        {
            return result;
        }

        var claims = new List<Claim>()
        {
            new(ClaimsIdentity.DefaultNameClaimType, "Visitor"),
            new(ClaimsIdentity.DefaultRoleClaimType, "Visitor"),
        };

        var identity = new ClaimsIdentity(claims, AuthenticationConstants.AuthenticationCookieVisitor);
        var principal = new ClaimsPrincipal(identity);

        await Context.SignInAsync(AuthenticationConstants.AuthenticationCookieVisitor, principal);

        return AuthenticateResult.Success(new AuthenticationTicket(principal,
            AuthenticationConstants.AuthenticationCookieVisitor));
    }
}