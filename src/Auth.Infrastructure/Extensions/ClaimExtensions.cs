using System.Security.Claims;

namespace Auth.Infrastructure.Extensions;

public static class ClaimExtensions
{
    public static Guid GetUserId(this ClaimsPrincipal user)
    {
        return Guid.Parse(user.Claims.FirstOrDefault(c => c.Type == "userId")?.Value);
    }

    public static string GetEmail(this ClaimsPrincipal user)
    {
        return user.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
    }

    public static IEnumerable<string> GetRoles(this ClaimsPrincipal user)
    {
        return user.Claims.Where(c => c.Type == "role").Select(c => c.Value);
    }
}