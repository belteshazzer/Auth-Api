using Microsoft.AspNetCore.Authorization;

namespace Infrastructure.Services.Auth;

public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    private readonly IAuthService _authService;
    
    public PermissionAuthorizationHandler(IAuthService authService)
    {
        _authService = authService;
    }
    
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true)
            return;
        
        var userId = context.User.FindFirst("userId")?.Value;
        if (string.IsNullOrEmpty(userId))
            return;
        
        var user = await _authService.FindByIdAsync(userId);
        if (user == null)
            return;
        
        // Check if user has the required permission
        if (await _authService.UserHasPermissionAsync(user, requirement.Permission))
        {
            context.Succeed(requirement);
        }
    }
}

public class PermissionRequirement : IAuthorizationRequirement
{
    public string Permission { get; }
    
    public PermissionRequirement(string permission)
    {
        Permission = permission;
    }
}