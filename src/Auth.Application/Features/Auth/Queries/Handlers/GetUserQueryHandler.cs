using Auth.Application.Features.Auth.Queries.Requests;
using Auth.Application.Interfaces.Auth;
using Auth.Domain.Entities.Auth;
using MediatR;

namespace Auth.Application.Features.Auth.Queries.Handlers;

public class GetUserQueryHandler : IRequestHandler<GetUserQuery, User?>
{
    private readonly IAuthService _authService;

    public GetUserQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<User?> Handle(GetUserQuery request, CancellationToken cancellationToken)
    {
        return await _authService.FindByIdAsync(request.UserId);
    }
}

public class GetUserByEmailQueryHandler : IRequestHandler<GetUserByEmailQuery, User?>
{
    private readonly IAuthService _authService;

    public GetUserByEmailQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<User?> Handle(GetUserByEmailQuery request, CancellationToken cancellationToken)
    {
        return await _authService.FindByEmailAsync(request.Email);
    }
}

public class GetUserByUserNameQueryHandler : IRequestHandler<GetUserByUserNameQuery, User?>
{
    private readonly IAuthService _authService;

    public GetUserByUserNameQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<User?> Handle(GetUserByUserNameQuery request, CancellationToken cancellationToken)
    {
        return await _authService.FindByNameAsync(request.UserName);
    }
}

public class GetUsersInRoleQueryHandler : IRequestHandler<GetUsersInRoleQuery, IList<User>>
{
    private readonly IAuthService _authService;

    public GetUsersInRoleQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IList<User>> Handle(GetUsersInRoleQuery request, CancellationToken cancellationToken)
    {
        return await _authService.GetUsersInRoleAsync(request.RoleName);
    }
}

public class GetUsersInPermissionQueryHandler : IRequestHandler<GetUsersInPermissionQuery, IList<User>>
{
    private readonly IAuthService _authService;

    public GetUsersInPermissionQueryHandler(IAuthService authService)
    {
        _authService = authService;
    }

    public async Task<IList<User>> Handle(GetUsersInPermissionQuery request, CancellationToken cancellationToken)
    {
        return await _authService.GetUsersWithPermissionAsync(request.Permission);
    }
}