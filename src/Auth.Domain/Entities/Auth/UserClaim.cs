using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Entities.Auth;
public class UserClaim : IdentityUserClaim<Guid>
{
    public virtual User User { get; set; }
}