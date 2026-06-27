using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace AuthenticationBasicsApp.Startup;

public static class OAuthExtensions
{
    public static AuthenticationBuilder AddOAuthSetup(this AuthenticationBuilder builder, ConfigurationManager configuration)
    {
        builder.AddOAuth(AuthenticationConstants.AuthenticationOAuth, options =>
        {
            // Where the OAuth handler persists the authenticated principal after callback.
            // Schema3 is a registered cookie scheme, so this is correct.
            options.SignInScheme = AuthenticationConstants.AuthenticationCookieSchema3;

            // Credentials — pull from configuration/user-secrets instead of hardcoding.
            options.ClientId = configuration["OAuth:ClientId"] ?? "id";
            options.ClientSecret = configuration["OAuth:ClientSecret"] ?? "secret";

            // Hosted mock OAuth2 provider (kogiqa) using Google-style paths, which
            // return a JSON token response. Its /authorize redirects back to redirect_uri
            // with code + echoed state, so the auth-code flow completes against localhost.
            options.AuthorizationEndpoint = "https://oauth.kogiqa.com/o/oauth2/v2/auth";
            options.TokenEndpoint = "https://oauth.kogiqa.com/oauth2/v4/token";
            options.UserInformationEndpoint = "https://oauth.kogiqa.com/oauth2/v3/userinfo";

            // Must match the redirect URI the provider/mock sends the browser back to,
            // and must NOT collide with an MVC route. "/signin-oauth" is the conventional default.
            options.CallbackPath = "/signin-oauth";

            options.Scope.Add("profile");
            options.Scope.Add("email");

            options.SaveTokens = true; // keep access/refresh tokens in auth properties
            options.UsePkce = true; // PKCE — recommended for the auth-code flow

            // Map user-info JSON fields onto claims (runs during OnCreatingTicket).
            options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
            options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
            options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");

            // After the token is obtained, call the user-info endpoint and let the
            // ClaimActions above populate the identity from the returned JSON.
            options.Events = new OAuthEvents
            {
                OnCreatingTicket = async ctx =>
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                    using var response = await ctx.Backchannel.SendAsync(
                        request, HttpCompletionOption.ResponseHeadersRead, ctx.HttpContext.RequestAborted);
                    response.EnsureSuccessStatusCode();

                    using var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    ctx.RunClaimActions(user.RootElement);
                }
            };
        });
        
        return  builder;
    }
}