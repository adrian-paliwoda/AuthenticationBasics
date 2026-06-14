using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AuthenticationBasicsApp.UserStore;

public class Database
{
    private static string UserHash(string username)
    {
        return Convert.ToBase64String(MD5.HashData(Encoding.UTF8.GetBytes(username)));
    }
    
    public async Task<User?> GetUserAsync(string username, CancellationToken cancellationToken)
    {
        var hash = UserHash(username);
        if (!File.Exists(hash))
        {
            return null;
        }
        
        await using var reader = File.OpenRead(hash);
        return await JsonSerializer.DeserializeAsync<User>(reader, cancellationToken: cancellationToken);
    }
    
    public async Task PutAsync(User user, CancellationToken cancellationToken)
    {
        var hash = UserHash(user.Username);

        await using var writer = File.OpenWrite(hash);
        await JsonSerializer.SerializeAsync(writer, user, cancellationToken: cancellationToken);
    }
}