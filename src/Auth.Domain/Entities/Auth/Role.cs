namespace Auth.Domain.Entities;
public class Role : IdentityRole<Guid>
{
    public string Description { get; set; }
    public bool IsSystemRole { get; set; } = false;
    
    public virtual ICollection<RoleClaim> RoleClaims { get; set; }
    public virtual ICollection<UserRole> UserRoles { get; set; }
    public virtual ICollection<RolePermission> RolePermissions { get; set; }
}