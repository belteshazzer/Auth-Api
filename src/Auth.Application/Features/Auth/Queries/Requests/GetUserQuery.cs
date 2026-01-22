using Auth.Domain.Entities.Auth;
using MediatR;

namespace Auth.Application.Features.Auth.Queries.Requests;

public class GetUserQuery : IRequest<User?>
{
    public Guid UserId { get; set; }
}

public class GetUserByEmailQuery : IRequest<User?>
{
    public string Email { get; set; } = null!;
}

public class GetUserByUserNameQuery : IRequest<User?>
{
    public string UserName { get; set; } = null!;
}

public class GetUsersInRoleQuery : IRequest<IList<User>>
{
    public string RoleName { get; set; } = null!;
}

public class GetUsersInPermissionQuery : IRequest<IList<User>>
{
    public string Permission { get; set; } = null!;
}

