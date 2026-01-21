using Auth.Application.Common.Models;
using MediatR;

namespace Auth.Application.Features.Auth.Commands.Requests;

public class RefreshTokenCommand : IRequest<Result<TokenResponse>>
{
    public required RefreshTokenRequest RefreshTokenRequest { get; set; }
}