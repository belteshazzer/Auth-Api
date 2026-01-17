using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Core.Application.Common.Interfaces;
using Core.Application.Common.Models;
using Core.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Services.Auth;

public interface IJwtService
{
    Task<TokenResponse> GenerateTokenAsync(User user);
    Task<TokenResponse> GenerateTokenAsync(User user, string refreshToken);
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    string GenerateRefreshToken();
}

public class JwtService : IJwtService
{
    private readonly IConfiguration _configuration;
    private readonly IIdentityService _identityService;
    
    public JwtService(
        IConfiguration configuration,
        IIdentityService identityService)
    {
        _configuration = configuration;
        _identityService = identityService;
    }
    
    public async Task<TokenResponse> GenerateTokenAsync(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["JwtSettings:Secret"]);
        
        var claims = await GetUserClaimsAsync(user);
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(
                double.Parse(_configuration["JwtSettings:TokenExpirationInMinutes"])),
            Issuer = _configuration["JwtSettings:Issuer"],
            Audience = _configuration["JwtSettings:Audience"],
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key), 
                SecurityAlgorithms.HmacSha256Signature)
        };
        
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);
        
        // Generate refresh token
        var refreshToken = GenerateRefreshToken();
        
        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = tokenDescriptor.Expires.Value
        };
    }
    
    public async Task<TokenResponse> GenerateTokenAsync(User user, string refreshToken)
    {
        var token = await GenerateTokenAsync(user);
        token.RefreshToken = refreshToken;
        return token;
    }
    
    private async Task<List<Claim>> GetUserClaimsAsync(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim("userId", user.Id.ToString()),
            new Claim("name", $"{user.FirstName} {user.LastName}"),
            new Claim("firstName", user.FirstName),
            new Claim("lastName", user.LastName),
            new Claim("isActive", user.IsActive.ToString()),
            new Claim("createdAt", user.CreatedAt.ToString("O"))
        };
        
        // Add roles
        var roles = await _identityService.GetUserRolesAsync(user);
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
            claims.Add(new Claim("roles", role));
        }
        
        // Add permissions
        var permissions = await _identityService.GetUserPermissionsAsync(user);
        foreach (var permission in permissions)
        {
            claims.Add(new Claim("Permission", permission));
        }
        
        // Add user-specific claims from database
        var userClaims = await _identityService.GetUserClaimsAsync(user);
        claims.AddRange(userClaims);
        
        // Add profile claims if available
        var profile = await _identityService.GetUserProfileAsync(user.Id);
        if (profile != null)
        {
            if (profile.DateOfBirth.HasValue)
                claims.Add(new Claim("dateOfBirth", profile.DateOfBirth.Value.ToString("O")));
                
            if (!string.IsNullOrEmpty(profile.Department))
                claims.Add(new Claim("department", profile.Department));
                
            claims.Add(new Claim("yearsOfService", profile.YearsOfService.ToString()));
        }
        
        return claims;
    }
    
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
    
    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["JwtSettings:Secret"])),
            ValidateLifetime = false
        };
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
        
        if (securityToken is not JwtSecurityToken jwtSecurityToken || 
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");
        
        return principal;
    }
}