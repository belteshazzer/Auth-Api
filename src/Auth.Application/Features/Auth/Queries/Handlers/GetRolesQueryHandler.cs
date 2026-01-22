using Auth.Application.Features.Auth.Queries.Requests;
using Auth.Application.Interfaces.Auth;
using Auth.Domain.Entities.Auth;
using MediatR;

namespace Auth.Application.Features.Auth.Queries.Handlers;

public class GetUserRolesQueryHandler : IRequestHandler<GetUserRolesQuery, IList<string>>
{
    private readonly IAuthService _authService;

    public GetUserRolesQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IList<string>> Handle(GetUserRolesQuery request, CancellationToken cancellationToken)
    {
        var user = await _authService.FindByIdAsync(request.UserId);
        if (user == null)
        {
            throw new KeyNotFoundException("User not found.");
        }
        return await _authService.GetUserRolesAsync(user);
    }
}

public class GetAllRolesQueryHandler : IRequestHandler<GetAllRolesQuery, IList<Role>>
{
    private readonly IAuthService _authService;

    public GetAllRolesQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IList<Role>> Handle(GetAllRolesQuery request, CancellationToken cancellationToken)
    {
        return await _authService.GetAllRolesAsync();
    }
}

public class GetRoleByIdQueryHandler : IRequestHandler<GetRoleByIdQuery, Role?>
{
    private readonly IAuthService _authService;

    public GetRoleByIdQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<Role?> Handle(GetRoleByIdQuery request, CancellationToken cancellationToken)
    {
        return await _authService.FindRoleByIdAsync(request.RoleId);
    }
}

public class GetRoleByNameQueryHandler : IRequestHandler<GetRoleByNameQuery, Role?>
{
    private readonly IAuthService _authService;

    public GetRoleByNameQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<Role?> Handle(GetRoleByNameQuery request, CancellationToken cancellationToken)
    {
        return await _authService.FindRoleByNameAsync(request.RoleName);
    }
}

public class IsInRoleQueryHandler : IRequestHandler<IsInRoleQuery, bool>
{
    private readonly IAuthService _authService;

    public IsInRoleQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<bool> Handle(IsInRoleQuery request, CancellationToken cancellationToken)
    {
        var user = await _authService.FindByIdAsync(request.UserId);
        if (user == null)
        {
            throw new KeyNotFoundException("User not found.");
        }
        return await _authService.IsInRoleAsync(user, request.RoleName);
    }
}