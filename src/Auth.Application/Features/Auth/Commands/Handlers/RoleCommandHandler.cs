using Auth.Application.Features.Auth.Commands.Requests;
using Auth.Application.Interfaces.Auth;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Auth.Application.Features.Auth.Commands.Handlers;

public class CreateRoleCommandHandler : IRequestHandler<CreateRoleCommand, IdentityResult>
{
    private readonly IAuthService _authService;

    public CreateRoleCommandHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IdentityResult> Handle(CreateRoleCommand request, CancellationToken cancellationToken)
    {
        return await _authService.CreateRoleAsync(request.RoleName, request.Description);
    }
}

public class DeleteRoleCommandHandler : IRequestHandler<DeleteRoleCommand, IdentityResult>
{
    private readonly IAuthService _authService;

    public DeleteRoleCommandHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IdentityResult> Handle(DeleteRoleCommand request, CancellationToken cancellationToken)
    {
        return await _authService.DeleteRoleAsync(request.RoleId);
    }
}

public class AssignRolesToUserCommandHandler : IRequestHandler<AssignRolesToUserCommand, IdentityResult>
{
    private readonly IAuthService _authService;

    public AssignRolesToUserCommandHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IdentityResult> Handle(AssignRolesToUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _authService.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return IdentityResult.Failed(new IdentityError { Description = "User not found." });
        }

        return await _authService.AssignRolesToUserAsync(user, request.Roles);
    }
}

public class RemoveRolesFromUserCommandHandler : IRequestHandler<RemoveRolesFromUserCommand, IdentityResult>
{
    private readonly IAuthService _authService;

    public RemoveRolesFromUserCommandHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IdentityResult> Handle(RemoveRolesFromUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _authService.FindByIdAsync(request.UserId);
        if (user == null)
        {
            return IdentityResult.Failed(new IdentityError { Description = "User not found." });
        }

        return await _authService.RemoveRolesFromUserAsync(user, request.Roles);
    }
}