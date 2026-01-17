namespace Auth.Domain.Entities;

public class Permission
{
    public string Name { get; set; }
    public string Description { get; set; }
    public string Module { get; set; }
    
    public virtual ICollection<UserPermission> UserPermissions { get; set; }
    public virtual ICollection<RolePermission> RolePermissions { get; set; }
}