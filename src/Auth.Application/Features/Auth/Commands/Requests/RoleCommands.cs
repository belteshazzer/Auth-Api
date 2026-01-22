using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Auth.Application.Features.Auth.Commands.Requests;

public class CreateRoleCommand : IRequest<IdentityResult>
{
    public string RoleName { get; set; } = null!;
    public string? Description { get; set; }
}

public class DeleteRoleCommand : IRequest<IdentityResult>
{
    public Guid RoleId { get; set; }
}

public class AssignRolesToUserCommand : IRequest<IdentityResult>
{
    public Guid UserId { get; set; }
    public IEnumerable<string> Roles { get; set; } = null!;
}

public class RemoveRolesFromUserCommand : IRequest<IdentityResult>
{
    public Guid UserId { get; set; }
    public IEnumerable<string> Roles { get; set; } = null!;
}

