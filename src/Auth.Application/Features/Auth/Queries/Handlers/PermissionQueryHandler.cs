using Auth.Application.Features.Auth.Queries.Requests;
using Auth.Application.Interfaces.Auth;
using Auth.Domain.Entities.Auth;
using MediatR;

namespace Auth.Application.Features.Auth.Queries.Handlers;

public class GetUserPermissionQueryHandler : IRequestHandler<GetUserPermissionQuery, IList<string>>
{
    private readonly IAuthService _authService;

    public GetUserPermissionQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }
    public async Task<IList<string>> Handle(GetUserPermissionQuery request, CancellationToken cancellationToken)
    {
        var user = await _authService.FindByIdAsync(request.UserId);
        if (user == null)
        {
            throw new KeyNotFoundException("User not found.");
        }
        return await _authService.GetUserPermissionsAsync(user);
    }
}

public class GetRolePermissionQueryHandler : IRequestHandler<GetRolePermissionQuery, IList<string>>
{
    private readonly IAuthService _authService;

    public GetRolePermissionQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IList<string>> Handle(GetRolePermissionQuery request, CancellationToken cancellationToken)
    {
        return await _authService.GetRolePermissionsAsync(request.RoleName);
    }
}

public class GetAllPermissionsQueryHandler : IRequestHandler<GetAllPermissionsQuery, IList<Permission>>
{
    private readonly IAuthService _authService;

    public GetAllPermissionsQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IList<Permission>> Handle(GetAllPermissionsQuery request, CancellationToken cancellationToken)
    {
        return await _authService.GetAllPermissionsAsync();
    }
}