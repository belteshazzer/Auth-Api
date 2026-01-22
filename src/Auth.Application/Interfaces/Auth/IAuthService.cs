using Auth.Domain.Entities.Auth;
using Microsoft.AspNetCore.Identity;

namespace Auth.Application.Interfaces.Auth;

public interface IAuthService
{
    Task<User> FindByEmailAsync(string email);
    Task<User> FindByIdAsync(Guid userId);
    Task<User> FindByNameAsync(string userName);
    Task<IdentityResult> CreateUserAsync(User user, string password);
    Task<IdentityResult> UpdateUserAsync(User user);
    Task<IdentityResult> DeleteUserAsync(Guid userId);
    Task<bool> CheckPasswordAsync(User user, string password);
    
    // Role management
    Task<IdentityResult> CreateRoleAsync(string roleName, string description = null);
    Task<IList<Role>> GetAllRolesAsync();
    Task<IdentityResult> DeleteRoleAsync(Guid roleId);
    Task<IList<string>> GetUserRolesAsync(User user);
    Task<IdentityResult> AssignRolesToUserAsync(User user, IEnumerable<string> roles);
    Task<IdentityResult> RemoveRolesFromUserAsync(User user, IEnumerable<string> roles);
    Task<bool> IsInRoleAsync(User user, string role);
    Task<Role?> FindRoleByIdAsync(Guid roleId);
    Task<Role?> FindRoleByNameAsync(string roleName);
    
    // Claim management
    Task<IList<System.Security.Claims.Claim>> GetUserClaimsAsync(User user);
    Task<IdentityResult> AddClaimToUserAsync(User user, System.Security.Claims.Claim claim);
    Task<IdentityResult> RemoveClaimFromUserAsync(User user, System.Security.Claims.Claim claim);
    
    // Permission management
    Task<Permission?> CreatePermissionAsync(string permissionName, string description = null, string module = null);
    Task<IList<Permission>> GetAllPermissionsAsync();
    Task<IdentityResult> AssignPermissionsToUserAsync(User user, IEnumerable<Guid> permissions);
    Task<IdentityResult> AssignPermissionsToRoleAsync(Role role, IEnumerable<Guid> permissions);
    Task<IdentityResult> RemovePermissionsFromRoleAsync(Role role, IEnumerable<Guid> permissions);
    Task<IdentityResult> RemovePermissionsFromUserAsync(User user, IEnumerable<Guid> permissions);
    Task<bool> UserHasPermissionAsync(User user, Guid permission);
    Task<IList<string>> GetUserPermissionsAsync(User user);
    Task<IList<string>> GetRolePermissionsAsync(string roleName);
    
    // Advanced queries
    Task<IList<User>> GetUsersInRoleAsync(string roleName);
    Task<IList<User>> GetUsersWithPermissionAsync(string permission);
    Task<bool> UserHasAnyPermissionAsync(User user, params string[] permissions);
    Task<bool> UserHasAllPermissionsAsync(User user, params string[] permissions);
    
    // Token management
    Task<RefreshToken?> GenerateRefreshTokenAsync(User user, string ipAddress);
    Task<RefreshToken?> GetRefreshTokenAsync(string token);
    Task RevokeRefreshTokenAsync(RefreshToken token, string ipAddress, string replacedByToken = null);
    Task RevokeDescendantRefreshTokensAsync(RefreshToken token, string ipAddress);
    
    // Profile management
    Task<UserProfile?> GetUserProfileAsync(Guid userId);
    Task<IdentityResult> UpdateUserProfileAsync(Guid userId, Action<UserProfile> updateAction);
}