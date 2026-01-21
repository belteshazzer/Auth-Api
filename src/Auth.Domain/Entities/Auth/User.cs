
using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Entities.Auth;

public class User : IdentityUser<Guid>
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public virtual ICollection<UserRole> UserRoles { get; set; }
    public virtual ICollection<UserClaim> Claims { get; set; }
    public virtual ICollection<UserPermission> Permissions { get; set; }
    public virtual UserProfile Profile { get; set; }
    public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = [];
}