using Microsoft.AspNetCore.Authorization;

public class MyRequirementHandler : AuthorizationHandler<MyRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MyRequirement requirement)
    {
        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}