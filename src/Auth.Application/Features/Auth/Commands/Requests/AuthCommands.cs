using MediatR;
using Auth.Application.Dtos.Auth;
using Auth.Application.Common.Models;

namespace Auth.Application.Features.Auth.Commands.Requests;

public class RegisterCommand : IRequest<Guid?>
{
    public RegisterUserDto RegisterUserDto { get; set; }
}

public class LoginCommand : IRequest<Result<AuthResponseDto>>
{
    public string Email { get; set; }
    public string Password { get; set; }
    public bool RememberMe { get; set; }
}

public class AssignPermissionsCommand : IRequest<Result>
{
    public Guid UserId { get; set; }
    public Guid[] Permissions { get; set; }
}

