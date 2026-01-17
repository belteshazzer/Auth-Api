using MediatR;
using Auth.Application.Features.Auth.Commands.Requests;
using System.IO.Pipelines;
using System.ComponentModel.DataAnnotations;

namespace Auth.Application.Features.Auth.Commands.Handlers;

public class RegisterCommandHandler : IRequestHandler<RegisterCommand, Guid>
{
    private readonly IAuthService _authService;
    private readonly IJwtService _jwtService;
    private readonly IMapper _mapper;

    public RegisterCommandHandler(IAuthService authService, IJwtService jwtService, IMapper mapper)
    {
        _authService = authService;
        _jwtService = jwtService;
        _mapper = mapper;
    }

    public async Task<Guid> Handle(RegisterCommand request, CancellationToken cancellationToken)
    {
        // validate request
        var userId = await _authService._authService.FindByEmailAsync(request.RegisterUserDto.Email);
        if (userId != null)
        {
            return ReadResult<AuthResponseDto>.Failure("User with this email already exists.");
        }

        var user = _mapper.Map<User>(request.RegisterUserDto);

        var result = await _authService.CreateUserAsync(user, request.RegisterUserDto.Password);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            return ReadResult<AuthResponseDto>.Failure($"User creation failed: {errors}");
        }

        if(request.RegisterUserDto.Roles != null && request.RegisterUserDto.Roles.Any())
        {
            var roleResult = await _authService.AssignRolesToUserAsync(user, request.RegisterUserDto.Roles);
            if (!roleResult.Succeeded)
            {
                var errors = string.Join(", ", roleResult.Errors.Select(e => e.Description));
                return ReadResult<AuthResponseDto>.Failure($"Assigning roles failed: {errors}");
            }
        }

        // Generate JWT token
        var token = await _jwtService.GenerateJwtTokenAsync(user);

        return Result<AuthResponseDto>.Success(new AuthResponseDto
        {
            UserId = user.Id,
            Token = token,
            RefreshToken = token.RefreshToken,
            ExpiresAt = token.ExpiresAt,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            UserName = user.UserName,
            Roles = request.RegisterUserDto.Roles
        });
    }
}

public class LoginCommandHandler : IRequestHandler<LoginCommand, Result<AuthResponse>>
{
    private readonly IAuthService _authService;
    private readonly IJwtService _jwtService;
    
    public LoginCommandHandler(
        IAuthService authService,
        IJwtService jwtService)
    {
        _authService = authService;
        _jwtService = jwtService;
    }
    
    public async Task<Result<AuthResponse>> Handle(
        LoginCommand request, 
        CancellationToken cancellationToken)
    {
        var user = await _authService.FindByEmailAsync(request.Email);
        
        if (user == null || !await _authService.CheckPasswordAsync(user, request.Password))
            return Result<AuthResponse>.Failure("Invalid credentials");
        
        if (!user.IsActive)
            return Result<AuthResponse>.Failure("Account is deactivated");
        
        // Generate JWT token
        var token = await _jwtService.GenerateTokenAsync(user);
        
        // Get user roles
        var roles = await _authService.GetUserRolesAsync(user);
        
        return Result<AuthResponse>.Success(new AuthResponse
        {
            Token = token,
            UserId = user.Id,
            Email = user.Email,
            UserName = user.UserName,
            Roles = roles
        });
    }
}

public class AssignPermissionsCommandHandler : IRequestHandler<AssignPermissionsCommand, Result>
{
    private readonly IAuthService _authService;
    
    public AssignPermissionsCommandHandler(IAuthService authService)
    {
        _authService = authService;
    }
    
    public async Task<Result> Handle(
        AssignPermissionsCommand request, 
        CancellationToken cancellationToken)
    {
        var user = await _authService.FindByIdAsync(request.UserId);
        
        if (user == null)
            return Result.Failure("User not found");
        
        var result = await _authService.AssignPermissionsToUserAsync(
            user, request.Permissions);
        
        return result.Succeeded 
            ? Result.Success() 
            : Result.Failure(result.Errors);
    }
}