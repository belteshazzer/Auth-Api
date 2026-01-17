namespace Auth.Domain.Entities;
public class UserClaim : IdentityUserClaim<Guid>
{
    public virtual User User { get; set; }
}