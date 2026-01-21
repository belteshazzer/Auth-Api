using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Entities.Auth;
public class UserRole : IdentityUserRole<Guid>
{
    public virtual User User { get; set; }
    public virtual Role Role { get; set; }
}