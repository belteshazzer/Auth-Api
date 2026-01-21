using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Entities.Auth;

public class RoleClaim : IdentityRoleClaim<Guid>
{
    public virtual Role Role { get; set; }
}