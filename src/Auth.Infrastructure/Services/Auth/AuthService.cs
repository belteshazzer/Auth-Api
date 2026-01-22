using System.Security.Claims;
using System.Security.Cryptography;
using Auth.Application.Interfaces.Auth;
using Auth.Domain.Entities.Auth;
using Auth.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Services.Auth;

public class AuthService : IAuthService
{
    private readonly UserManager<User> _userManager;
    private readonly RoleManager<Role> _roleManager;
    private readonly AuthDbContext _context;
    
    public AuthService(
        UserManager<User> userManager,
        RoleManager<Role> roleManager,
        AuthDbContext context)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _context = context;
    }
    
    #region User Management
    public async Task<User?> FindByEmailAsync(string email)
    {
        
        return await _userManager.FindByEmailAsync(email) ;
    }
    
    public async Task<User?> FindByIdAsync(Guid userId)
    {
        return await _userManager.FindByIdAsync(userId.ToString()) ;
    }
    
    public async Task<User?> FindByNameAsync(string userName)
    {
        return await _userManager.FindByNameAsync(userName);
    }
    
    public async Task<IdentityResult> CreateUserAsync(User user, string password)
    {
        return await _userManager.CreateAsync(user, password);
    }
    
    public async Task<IdentityResult> UpdateUserAsync(User user)
    {
        return await _userManager.UpdateAsync(user);
    }
    
    public async Task<IdentityResult> DeleteUserAsync(Guid userId)
    {
        var user = await FindByIdAsync(userId);
        return user == null 
            ? IdentityResult.Failed(new IdentityError { Description = "User not found" })
            : await _userManager.DeleteAsync(user);
    }
    
    public async Task<bool> CheckPasswordAsync(User user, string password)
    {
        return await _userManager.CheckPasswordAsync(user, password);
    }
    #endregion
    
    #region Role Management
    public async Task<IdentityResult> CreateRoleAsync(string roleName, string description = null)
    {
        var role = new Role
        {
            Name = roleName,
            Description = description,
            CreatedAt = DateTime.UtcNow
        };
        
        return await _roleManager.CreateAsync(role);
    }

    public async Task<IList<Role>> GetAllRolesAsync()
    {
        return await _roleManager.Roles.ToListAsync();
    }
    
    public async Task<IdentityResult> DeleteRoleAsync(Guid roleId)
    {
        var role = await FindRoleByIdAsync(roleId);
        return role == null 
            ? IdentityResult.Failed(new IdentityError { Description = "Role not found" })
            : await _roleManager.DeleteAsync(role);
    }
    
    public async Task<Role?> FindRoleByIdAsync(Guid roleId)
    {
        return await _roleManager.FindByIdAsync(roleId.ToString());
    }
    
    public async Task<Role?> FindRoleByNameAsync(string roleName)
    {
        return await _roleManager.FindByNameAsync(roleName);
    }
    
    public async Task<IList<string>> GetUserRolesAsync(User user)
    {
        return await _userManager.GetRolesAsync(user);
    }
    
    public async Task<IdentityResult> AssignRolesToUserAsync(User user, IEnumerable<string> roles)
    {
        return await _userManager.AddToRolesAsync(user, roles);
    }
    
    public async Task<IdentityResult> RemoveRolesFromUserAsync(User user, IEnumerable<string> roles)
    {
        return await _userManager.RemoveFromRolesAsync(user, roles);
    }
    
    public async Task<bool> IsInRoleAsync(User user, string role)
    {
        return await _userManager.IsInRoleAsync(user, role);
    }
    
    public async Task<IList<User>> GetUsersInRoleAsync(string roleName)
    {
        return await _userManager.GetUsersInRoleAsync(roleName);
    }
    #endregion
    
    #region Permission Management

    public async Task<Permission?> CreatePermissionAsync(string permissionName, string description = null, string module = null)
    {
        var existingPermission = await _context.Permissions
            .FirstOrDefaultAsync(p => p.Name == permissionName);
            
        if (existingPermission != null)
            return null; 
            
        var permission = new Permission
        {
            Id = Guid.NewGuid(),
            Name = permissionName,
            Description = description,
            Module = module
        };
        
        _context.Permissions.Add(permission);
        await _context.SaveChangesAsync();
        
        return permission;
    }


    public async Task<IdentityResult> AssignPermissionsToUserAsync(
        User user, 
        IEnumerable<Guid> permissions)
    {
        var existingPermissions = await _context.UserPermissions
            .Where(up => up.UserId == user.Id)
            .Select(up => up.Permission.Id)
            .ToListAsync();
            
        // Find permissions to add
        var permissionsToAdd = permissions
            .Except(existingPermissions)
            .ToList();
            
        // Get permission entities
        var permissionEntities = await _context.Permissions
            .Where(p => permissionsToAdd.Contains(p.Id))
            .ToListAsync();
            
        foreach (var permission in permissionEntities)
        {
            var userPermission = new UserPermission
            {
                UserId = user.Id,
                PermissionId = permission.Id,
                GrantedAt = DateTime.UtcNow
            };
            
            _context.UserPermissions.Add(userPermission);
        }
        
        await _context.SaveChangesAsync();
        
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> AssignPermissionsToRoleAsync(
        Role role, 
        IEnumerable<Guid> permissions)
    {
        var existingPermissions = await _context.RolePermissions
            .Where(rp => rp.RoleId == role.Id)
            .Select(rp => rp.Permission.Id)
            .ToListAsync();
            
        // Find permissions to add
        var permissionsToAdd = permissions
            .Except(existingPermissions)
            .ToList();
            
        // Get permission entities
        var permissionEntities = await _context.Permissions
            .Where(p => permissionsToAdd.Contains(p.Id))
            .ToListAsync();
            
        foreach (var permission in permissionEntities)
        {
            var rolePermission = new RolePermission
            {
                RoleId = role.Id,
                PermissionId = permission.Id,
            };
            
            _context.RolePermissions.Add(rolePermission);
        }
        
        await _context.SaveChangesAsync();
        
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> RemovePermissionsFromUserAsync(User user, IEnumerable<Guid> permissions)
    {
        var userPermissions = await _context.UserPermissions
            .Where(up => up.UserId == user.Id && permissions.Contains(up.PermissionId))
            .ToListAsync();
            
        _context.UserPermissions.RemoveRange(userPermissions);
        await _context.SaveChangesAsync();
        
        return IdentityResult.Success;
    }
    public async Task<IdentityResult> RemovePermissionsFromRoleAsync(Role role, IEnumerable<Guid> permissions)
    {
        var rolePermissions = await _context.RolePermissions
            .Where(rp => rp.RoleId == role.Id && permissions.Contains(rp.PermissionId))
            .ToListAsync();
            
        _context.RolePermissions.RemoveRange(rolePermissions);
        await _context.SaveChangesAsync();
        
        return IdentityResult.Success;
    }
    
    public async Task<bool> UserHasPermissionAsync(User user, Guid permission)
    {
        return await _context.UserPermissions
            .Include(up => up.Permission)
            .AnyAsync(up => 
                up.UserId == user.Id && 
                up.Permission.Id == permission);
    }
    
    public async Task<IList<string>> GetUserPermissionsAsync(User user)
    {
        return await _context.UserPermissions
            .Include(up => up.Permission)
            .Where(up => up.UserId == user.Id)
            .Select(up => up.Permission.Name)
            .ToListAsync();
    }
    
    public async Task<IList<string>> GetRolePermissionsAsync(string roleName)
    {
        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
            return new List<string>();
            
        return await _context.RolePermissions
            .Include(rp => rp.Permission)
            .Include(rp => rp.Role)
            .Where(rp => rp.RoleId == role.Id)
            .Select(rp => rp.Permission.Name)
            .ToListAsync();
    }
    
    public async Task<IList<User>> GetUsersWithPermissionAsync(string permission)
    {
        return await _context.UserPermissions
            .Include(up => up.User)
            .Include(up => up.Permission)
            .Where(up => up.Permission.Name == permission)
            .Select(up => up.User)
            .ToListAsync();
    }
    
    public async Task<bool> UserHasAnyPermissionAsync(User user, params string[] permissions)
    {
        var userPermissions = await GetUserPermissionsAsync(user);
        return permissions.Any(p => userPermissions.Contains(p));
    }
    
    public async Task<bool> UserHasAllPermissionsAsync(User user, params string[] permissions)
    {
        var userPermissions = await GetUserPermissionsAsync(user);
        return permissions.All(p => userPermissions.Contains(p));
    }

    public async Task<IList<Permission>> GetAllPermissionsAsync()
    {
        return await _context.Permissions.ToListAsync();
    }

    #endregion
    
    #region Token Management
    public async Task<RefreshToken> GenerateRefreshTokenAsync(User user, string ipAddress)
    {
        var refreshToken = new RefreshToken
        {
            UserId = user.Id,
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            Expires = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };
        
        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();
        
        return refreshToken;
    }
    
    public async Task<RefreshToken?> GetRefreshTokenAsync(string token)
    {
        return await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == token);
    }
    
    public async Task RevokeRefreshTokenAsync(
        RefreshToken token, 
        string ipAddress, 
        string? replacedByToken = null)
    {
        token.Revoked = DateTime.UtcNow;
        token.RevokedByIp = ipAddress;
        token.ReplacedByToken = replacedByToken;
        
        _context.RefreshTokens.Update(token);
        await _context.SaveChangesAsync();
    }
    
    public async Task RevokeDescendantRefreshTokensAsync(RefreshToken token, string ipAddress)
    {
        if (!string.IsNullOrEmpty(token.ReplacedByToken))
        {
            var childToken = await GetRefreshTokenAsync(token.ReplacedByToken);
            if (childToken != null)
            {
                await RevokeRefreshTokenAsync(childToken, ipAddress);
                await RevokeDescendantRefreshTokensAsync(childToken, ipAddress);
            }
        }
    }
    #endregion
    
    #region Profile Management
    public async Task<UserProfile?> GetUserProfileAsync(Guid userId)
    {
        return await _context.UserProfiles
            .FirstOrDefaultAsync(up => up.UserId == userId);
    }
    
    public async Task<IdentityResult> UpdateUserProfileAsync(Guid userId, Action<UserProfile> updateAction)
    {
        var profile = await GetUserProfileAsync(userId);
        
        if (profile == null)
        {
            profile = new UserProfile
            {
                Id = Guid.NewGuid(),
                UserId = userId
            };
            _context.UserProfiles.Add(profile);
        }
        
        updateAction(profile);
        
        await _context.SaveChangesAsync();
        
        return IdentityResult.Success;
    }
    #endregion
    
    #region Claim Management
    public async Task<IList<Claim>> GetUserClaimsAsync(User user)
    {
        return await _userManager.GetClaimsAsync(user);
    }
    
    public async Task<IdentityResult> AddClaimToUserAsync(User user, Claim claim)
    {
        return await _userManager.AddClaimAsync(user, claim);
    }
    
    public async Task<IdentityResult> RemoveClaimFromUserAsync(User user, Claim claim)
    {
        return await _userManager.RemoveClaimAsync(user, claim);
    }
    #endregion
}