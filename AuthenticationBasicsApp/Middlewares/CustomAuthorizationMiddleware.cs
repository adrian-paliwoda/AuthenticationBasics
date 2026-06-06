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