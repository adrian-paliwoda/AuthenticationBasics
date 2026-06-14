using System.Security.Claims;
using AuthenticationBasicsApp.Models;

namespace AuthenticationBasicsApp.UserStore;

public class UserHelper
{
    public static ClaimsPrincipal ConvertToClaimsPrincipal(User user)
    {
        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, user.Username),
        };
        
        claims.AddRange(user.Claims.Select(claim => new Claim(claim.Type, claim.Value)));
        var identity = new ClaimsIdentity(claims, AuthenticationConstants.AuthenticationCookieSchema);
        
        return new ClaimsPrincipal(identity);
    }
}