namespace Auth.Domain.Entities.Auth;

public class RolePermission
{
    public Guid RoleId { get; set; }
    public Guid PermissionId { get; set; }

    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;
    
    public virtual Role Role { get; set; }
    public virtual Permission Permission { get; set; }
}