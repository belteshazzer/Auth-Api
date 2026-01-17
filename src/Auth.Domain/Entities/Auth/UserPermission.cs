namespace Auth.Domain.Entities;

public class UserPermission
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public Guid PermissionId { get; set; }
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;
    public string GrantedBy { get; set; }
    
    public virtual User User { get; set; }
    public virtual Permission Permission { get; set; }
}