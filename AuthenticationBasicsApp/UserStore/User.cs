namespace AuthenticationBasicsApp.UserStore;

public class User
{
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public List<UserClaim> Claims { get; set; } = [];
}