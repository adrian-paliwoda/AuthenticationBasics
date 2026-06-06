using AuthenticationBasicsApp.Models;

namespace AuthenticationBasicsApp.Services;

public class CustomAuthorizationService : ICustomAuthorizationService
{
    private readonly HttpContext _context;

    public CustomAuthorizationService(IHttpContextAccessor httpContextAccessor)
    {
        _context = httpContextAccessor.HttpContext ?? throw new ArgumentNullException(nameof(httpContextAccessor));
    }

    public bool CanGoToSweden()
    {
        if (_context.User.HasClaim(AuthenticationConstants.Passport, "eu"))
        {
            return true;
        }

        return false;
    }

    public bool CanGoToNorway()
    {
        if (_context.User.HasClaim(AuthenticationConstants.Passport, "nor"))
        {
            return true;
        }

        return false;
    }

    public bool CanGoToUsa()
    {
        if (_context.User.HasClaim(AuthenticationConstants.Visa, "usa"))
        {
            return true;
        }

        return false;
    }
}