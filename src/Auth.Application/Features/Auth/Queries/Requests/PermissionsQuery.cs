using Auth.Domain.Entities.Auth;
using MediatR;

namespace Auth.Application.Features.Auth.Queries.Requests;

public class GetUserPermissionQuery : IRequest<IList<string>>
{
    public Guid UserId { get; set; }
}

public class GetRolePermissionQuery : IRequest<IList<string>>
{
    public string RoleName { get; set; } = null!;
}

public class UserHasPermissionQuery : IRequest<bool>
{
    public Guid UserId { get; set; }
    public Guid PermissionId { get; set; }
}

public class GetAllPermissionsQuery : IRequest<IList<Permission>>
{
}