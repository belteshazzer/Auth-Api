using Auth.Domain.Entities.Auth;
using MediatR;

namespace Auth.Application.Features.Auth.Queries.Requests;

public class GetUserRolesQuery : IRequest<IList<string>>
{
    public Guid UserId { get; set; }
}

public class GetAllRolesQuery : IRequest<IList<Role>>
{
}

public class GetRoleByIdQuery : IRequest<Role?>
{
    public Guid RoleId { get; set; }
}

public class GetRoleByNameQuery : IRequest<Role?>
{
    public string RoleName { get; set; } = null!;
}

public class IsInRoleQuery : IRequest<bool>
{
    public Guid UserId { get; set; }
    public string RoleName { get; set; } = null!;
}

