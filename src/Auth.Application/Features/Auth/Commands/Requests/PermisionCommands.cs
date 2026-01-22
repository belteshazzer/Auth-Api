using Auth.Domain.Entities.Auth;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Auth.Application.Features.Auth.Commands.Requests;

public class CreatePermissionCommand : IRequest<Permission?>
{
    public string PermissionName { get; set; } = null!;
    public string? Description { get; set; }
    public string? Module { get; set; }
}

public class AssignPermissionsToUserCommand : IRequest<IdentityResult>
{
    public Guid UserId { get; set; }
    public IEnumerable<Guid> Permissions { get; set; } = null!;
}

public class RemovePermissionsFromUserCommand : IRequest<IdentityResult>
{
    public Guid UserId { get; set; }
    public IEnumerable<Guid> Permissions { get; set; } = null!;
}

