using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationBasicsApp.UserStore;

public class InMemoryUserStore :
    IUserPasswordStore<IdentityUser>,
    IUserRoleStore<IdentityUser>,
    IUserClaimStore<IdentityUser>
{
    private static readonly ConcurrentDictionary<string, IdentityUser> Users = new();
    private static readonly ConcurrentDictionary<string, HashSet<string>> Roles = new();
    private static readonly ConcurrentDictionary<string, List<Claim>> Claims = new();

    public Task<IdentityResult> CreateAsync(IdentityUser user, CancellationToken ct)
    {
        Users[user.Id] = user;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityUser?> FindByNameAsync(string normalizedName, CancellationToken ct)
    {
        return Task.FromResult(Users.Values
            .FirstOrDefault(u => u.NormalizedUserName == normalizedName));
    }

    public Task<IdentityUser?> FindByIdAsync(string userId, CancellationToken ct)
    {
        return Task.FromResult(Users.GetValueOrDefault(userId));
    }

    public Task<string> GetUserIdAsync(IdentityUser u, CancellationToken ct)
    {
        return Task.FromResult(u.Id);
    }

    public Task<string?> GetUserNameAsync(IdentityUser u, CancellationToken ct)
    {
        return Task.FromResult(u.UserName);
    }

    public Task SetUserNameAsync(IdentityUser u, string? name, CancellationToken ct)
    {
        u.UserName = name;
        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedUserNameAsync(IdentityUser u, CancellationToken ct)
    {
        return Task.FromResult(u.NormalizedUserName);
    }

    public Task SetNormalizedUserNameAsync(IdentityUser u, string? n, CancellationToken ct)
    {
        u.NormalizedUserName = n;
        return Task.CompletedTask;
    }

    public Task SetPasswordHashAsync(IdentityUser u, string? hash, CancellationToken ct)
    {
        u.PasswordHash = hash;
        return Task.CompletedTask;
    }

    public Task<string?> GetPasswordHashAsync(IdentityUser u, CancellationToken ct)
    {
        return Task.FromResult(u.PasswordHash);
    }

    public Task<bool> HasPasswordAsync(IdentityUser u, CancellationToken ct)
    {
        return Task.FromResult(u.PasswordHash != null);
    }

    public Task<IdentityResult> UpdateAsync(IdentityUser u, CancellationToken ct)
    {
        Users[u.Id] = u;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(IdentityUser u, CancellationToken ct)
    {
        Users.TryRemove(u.Id, out _);
        Roles.TryRemove(u.Id, out _);
        Claims.TryRemove(u.Id, out _);
        return Task.FromResult(IdentityResult.Success);
    }

    public Task AddToRoleAsync(IdentityUser u, string roleName, CancellationToken ct)
    {
        Roles.GetOrAdd(u.Id, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase))
            .Add(roleName);
        return Task.CompletedTask;
    }

    public Task RemoveFromRoleAsync(IdentityUser u, string roleName, CancellationToken ct)
    {
        if (Roles.TryGetValue(u.Id, out var set))
        {
            set.Remove(roleName);
        }

        return Task.CompletedTask;
    }

    public Task<IList<string>> GetRolesAsync(IdentityUser u, CancellationToken ct)
    {
        IList<string> roles = Roles.TryGetValue(u.Id, out var set)
            ? set.ToList()
            : new List<string>();
        return Task.FromResult(roles);
    }

    public Task<bool> IsInRoleAsync(IdentityUser u, string roleName, CancellationToken ct)
    {
        var inRole = Roles.TryGetValue(u.Id, out var set) && set.Contains(roleName);
        return Task.FromResult(inRole);
    }

    public Task<IList<IdentityUser>> GetUsersInRoleAsync(string roleName, CancellationToken ct)
    {
        IList<IdentityUser> users = Users.Values
            .Where(u => Roles.TryGetValue(u.Id, out var set) && set.Contains(roleName))
            .ToList();
        return Task.FromResult(users);
    }

    public Task<IList<Claim>> GetClaimsAsync(IdentityUser u, CancellationToken ct)
    {
        IList<Claim> claims = Claims.TryGetValue(u.Id, out var list)
            ? list.ToList()
            : new List<Claim>();
        return Task.FromResult(claims);
    }

    public Task AddClaimsAsync(IdentityUser u, IEnumerable<Claim> claims, CancellationToken ct)
    {
        Claims.GetOrAdd(u.Id, _ => new List<Claim>()).AddRange(claims);
        return Task.CompletedTask;
    }

    public Task ReplaceClaimAsync(IdentityUser u, Claim claim, Claim newClaim, CancellationToken ct)
    {
        if (Claims.TryGetValue(u.Id, out var list))
        {
            list.RemoveAll(c => c.Type == claim.Type && c.Value == claim.Value);
            list.Add(newClaim);
        }

        return Task.CompletedTask;
    }

    public Task RemoveClaimsAsync(IdentityUser u, IEnumerable<Claim> claims, CancellationToken ct)
    {
        if (Claims.TryGetValue(u.Id, out var list))
        {
            foreach (var c in claims)
            {
                list.RemoveAll(x => x.Type == c.Type && x.Value == c.Value);
            }
        }

        return Task.CompletedTask;
    }

    public Task<IList<IdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken ct)
    {
        IList<IdentityUser> users = Users.Values
            .Where(u => Claims.TryGetValue(u.Id, out var list)
                        && list.Any(c => c.Type == claim.Type && c.Value == claim.Value))
            .ToList();
        return Task.FromResult(users);
    }

    public void Dispose()
    {
    }
}