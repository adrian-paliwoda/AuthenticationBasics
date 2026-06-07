using Microsoft.AspNetCore.Identity;

namespace AuthenticationBasicsApp.UserStore;

// By default Identity uppercases names/roles (UpperInvariantLookupNormalizer),
// so GetRolesAsync would return "MANAGER" and [Authorize(Roles="manager")] would fail
// (role claim values are compared case-sensitively). This keeps original casing.
public class NoOpLookupNormalizer : ILookupNormalizer
{
    public string? NormalizeName(string? name) => name;
    public string? NormalizeEmail(string? email) => email;
}
