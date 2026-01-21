using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Entities.Auth;
public class Role : IdentityRole<Guid>
{
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public Guid? CreatedBy { get; set; }
    public string Description { get; set; }
    public bool IsSystemRole { get; set; } = false;
    
    public virtual ICollection<RoleClaim> RoleClaims { get; set; }
    public virtual ICollection<UserRole> UserRoles { get; set; }
    public virtual ICollection<RolePermission> RolePermissions { get; set; }
}