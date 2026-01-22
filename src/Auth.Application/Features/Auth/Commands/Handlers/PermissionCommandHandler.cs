using Auth.Application.Features.Auth.Commands.Requests;
using Auth.Application.Interfaces.Auth;
using Auth.Domain.Entities.Auth;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Auth.Application.Features.Auth.Commands.Handlers;

public class CreatePermissionCommandHandler : IRequestHandler<CreatePermissionCommand, Permission?>
{
    private readonly IAuthService _authService;

    public CreatePermissionCommandHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<Permission?> Handle(CreatePermissionCommand request, CancellationToken cancellationToken)
    {
        return await _authService.CreatePermissionAsync(request.PermissionName, request.Description, request.Module);
    }
}

public class AssignPermissionsToUserCommandHandler : IRequestHandler<AssignPermissionsToUserCommand, IdentityResult>
{
    private readonly IAuthService _authService;

    public AssignPermissionsToUserCommandHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IdentityResult> Handle(AssignPermissionsToUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _authService.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return IdentityResult.Failed(new IdentityError { Description = "User not found." });
        }

        return await _authService.AssignPermissionsToUserAsync(user, request.Permissions);
    }
}

public class RemovePermissionsFromUserCommandHandler : IRequestHandler<RemovePermissionsFromUserCommand, IdentityResult>
{
    private readonly IAuthService _authService;

    public RemovePermissionsFromUserCommandHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IdentityResult> Handle(RemovePermissionsFromUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _authService.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return IdentityResult.Failed(new IdentityError { Description = "User not found." });
        }

        return await _authService.RemovePermissionsFromUserAsync(user, request.Permissions);
    }
}