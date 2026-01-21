using Auth.Application.Common.Models;
using Auth.Domain.Entities.Auth;

namespace Auth.Application.Interfaces.Auth
{
    public interface IJwtService
    {
        Task<TokenResponse> GenerateTokenAsync(User user);
        Task<TokenResponse> GenerateTokenAsync(string refreshToken);
    }
}