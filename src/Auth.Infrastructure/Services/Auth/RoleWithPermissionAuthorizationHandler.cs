using Auth.Application.Interfaces.Auth;
using Microsoft.AspNetCore.Authorization;

namespace Infrastructure.Identity.Authorization;

public class RoleWithPermissionAuthorizationHandler : 
    AuthorizationHandler<RoleWithPermissionRequirement>
{
    private readonly IAuthService _authService;
    
    public RoleWithPermissionAuthorizationHandler(IAuthService authService)
    {
        _authService = authService;
    }
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        RoleWithPermissionRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true)
            return;
        
        var userId = context.User.FindFirst("userId")?.Value;
        if (string.IsNullOrEmpty(userId))
            return;
        
        var user = await _authService.FindByIdAsync(Guid.Parse(userId));
        if (user == null)
            return;
        
        // Check if user has the required role
        var userRoles = await _authService.GetUserRolesAsync(user);
        if (!userRoles.Contains(requirement.Role))
            return;
        
        // Check if user has the required permission
        if (await _authService.UserHasPermissionAsync(user, requirement.Permission))
        {
            context.Succeed(requirement);
        }
    }
}

public class RoleWithPermissionRequirement : IAuthorizationRequirement
{
    public string Role { get; }
    public Guid Permission { get; }
    
    public RoleWithPermissionRequirement(string role, Guid permission)
    {
        Role = role;
        Permission = permission;
    }
}