using AuthenticationBasicsApp.Models;

namespace AuthenticationBasicsApp.Polices;

public static class AuthenticationPoliciesExtension
{
    public static IServiceCollection AddAuthenticationPolicies(this IServiceCollection services)
    {
        return services.AddAuthorizationBuilder()
            .AddPolicy("eu passport", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.AddAuthenticationSchemes(AuthenticationConstants.AuthenticationCookieSchema);
                policy.RequireClaim(AuthenticationConstants.Passport, "eu");
            })
            .AddPolicy("usa", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.AddAuthenticationSchemes(AuthenticationConstants.AuthenticationCookieSchema2);
                policy.RequireClaim(AuthenticationConstants.Visa, "usa");
            })
            .AddPolicy("customer", policy =>
            {
                policy.AddAuthenticationSchemes(AuthenticationConstants.AuthenticationCookieSchema,
                        AuthenticationConstants.AuthenticationCookieVisitor)
                    .RequireAuthenticatedUser();
            })
            .AddPolicy("user", policy =>
            {
                policy.AddAuthenticationSchemes(AuthenticationConstants.AuthenticationCookieSchema)
                    .RequireAuthenticatedUser();
            })
            .Services;
    }
}