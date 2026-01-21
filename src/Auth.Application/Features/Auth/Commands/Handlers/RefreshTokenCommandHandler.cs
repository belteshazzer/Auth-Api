using Auth.Application.Common.Models;
using Auth.Application.Features.Auth.Commands.Requests;
using Auth.Application.Interfaces.Auth;
using MediatR;

namespace Auth.Application.Features.Auth.Commands.Handlers;

public class RefreshTokenCommandHandler : IRequestHandler<RefreshTokenCommand, Result<TokenResponse>>
{
    private readonly IAuthService _authService;
    private readonly IJwtService _jwtService;

    public RefreshTokenCommandHandler(IAuthService authService, IJwtService jwtService)
    {
        _authService = authService;
        _jwtService = jwtService;
    }

    public async Task<Result<TokenResponse>> Handle(RefreshTokenCommand request, CancellationToken cancellationToken)
    {
        var tokenResponse = await _jwtService.GenerateTokenAsync(request.RefreshTokenRequest.RefreshToken);

        var authResponse = new TokenResponse
        {
            AccessToken = tokenResponse.AccessToken,
            RefreshToken = tokenResponse.RefreshToken,
            ExpiresAt = tokenResponse.ExpiresAt
        };

        return Result<TokenResponse>.Success(authResponse);
    }
}