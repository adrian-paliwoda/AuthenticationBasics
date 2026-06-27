using System.Security.Claims;
using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationBasicsApp.UserStore;

public class UserManagerHelper
{
    public static async Task SetupUsersAsync(WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetService<UserManager<IdentityUser>>();

        if (userManager != null)
        {
            var userName = "adrian";
            var password = "test";

            if (await userManager.FindByNameAsync(userName) is null)
            {
                var user = new IdentityUser()
                {
                    UserName = userName,
                    Email = userName,
                    EmailConfirmed = true,
                    PhoneNumberConfirmed = true,
                };

                var result = await userManager.CreateAsync(user, password);
                if (!result.Succeeded)
                {
                    throw new Exception("Seeding user failed: " +
                                        string.Join("; ", result.Errors.Select(e => e.Description)));
                }

                var claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name, userName),
                    new Claim(ClaimTypes.Role, "admin"),
                    new Claim(ClaimTypes.Role, "manager"),
                    new Claim(ClaimTypes.Role, "user"),
                    new Claim(AuthenticationConstants.Passport, "eu"),
                    new Claim(AuthenticationConstants.Passport, "nor"),
                };

                await userManager.AddToRolesAsync(user, ["user", "admin", "manager"]);
                await userManager.AddClaimsAsync(user, claims);
            }
        }
    }
    
}