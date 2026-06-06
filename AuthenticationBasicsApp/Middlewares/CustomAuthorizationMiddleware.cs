using AuthenticationBasicsApp.Models;

namespace AuthenticationBasicsApp.Middlewares;

public class CustomAuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    
    public CustomAuthorizationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments("/api/auth/login"))
        {
            await _next(context);
            return;
        }
        
        if(context.User.Identities.All(identity => identity.AuthenticationType != AuthenticationConstants.AuthenticationCookieSchema2))
        {
            context.Response.StatusCode = 401;
            return;
        }
        
        await _next(context);
    }
}

public static class CustomAuthorizationMiddlewareExtensions
{
    public static IApplicationBuilder UseCustomAuthorizationMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<CustomAuthorizationMiddleware>();
    }
}