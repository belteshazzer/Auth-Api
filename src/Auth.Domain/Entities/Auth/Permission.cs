using System;
using System.Collections.Generic;

namespace Auth.Domain.Entities.Auth;

public class Permission
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; }
    public string Description { get; set; }
    public string Module { get; set; }

    public virtual ICollection<UserPermission> UserPermissions { get; set; }
    public virtual ICollection<RolePermission> RolePermissions { get; set; }
}