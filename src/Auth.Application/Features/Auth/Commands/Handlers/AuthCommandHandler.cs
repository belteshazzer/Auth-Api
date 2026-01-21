using MediatR;
using Auth.Application.Features.Auth.Commands.Requests;
using System.ComponentModel.DataAnnotations;
using Auth.Application.Common.Models;
using Auth.Application.Interfaces.Auth;
using Auth.Domain.Entities.Auth;
using AutoMapper;

namespace Auth.Application.Features.Auth.Commands.Handlers;

public class RegisterCommandHandler : IRequestHandler<RegisterCommand, Guid?>
{
    private readonly IAuthService _authService;
    private readonly IMapper _mapper;

    public RegisterCommandHandler(IAuthService authService, IMapper mapper)
    {
        _authService = authService;
        _mapper = mapper;
    }

    public async Task<Guid?> Handle(RegisterCommand request, CancellationToken cancellationToken)
    {
        // validate request
        var userId = await _authService.FindByEmailAsync(request.RegisterUserDto.Email);
        if (userId != null)
        {
            throw new ValidationException("Email is already registered");
        }

        var user = _mapper.Map<User>(request.RegisterUserDto);

        var result = await _authService.CreateUserAsync(user, request.RegisterUserDto.Password);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new ValidationException($"User creation failed: {errors}");
        }

        if(request.RegisterUserDto.Roles != null && request.RegisterUserDto.Roles.Any())
        {
            var roleResult = await _authService.AssignRolesToUserAsync(user, request.RegisterUserDto.Roles);
            if (!roleResult.Succeeded)
            {
                var errors = string.Join(", ", roleResult.Errors.Select(e => e.Description));
                throw new ValidationException($"Assigning roles failed: {errors}");
            }
        }

        // Generate JWT token
        // var token = await _jwtService.GenerateTokenAsync(user);

        // return Result<AuthResponseDto>.Success(new AuthResponseDto
        // {
        //     UserId = user.Id,
        //     Token = token,
        //     RefreshToken = token.RefreshToken,
        //     ExpiresAt = token.ExpiresAt,
        //     Email = user.Email,
        //     FirstName = user.FirstName,
        //     LastName = user.LastName,
        //     Roles = request.RegisterUserDto.Roles
        // });

        return user.Id;
    }
}

public class LoginCommandHandler : IRequestHandler<LoginCommand, Result<AuthResponseDto>>
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
    
    public async Task<Result<AuthResponseDto>> Handle(
        LoginCommand request, 
        CancellationToken cancellationToken)
    {
        var user = await _authService.FindByEmailAsync(request.Email);
        
        if (user == null || !await _authService.CheckPasswordAsync(user, request.Password))
            return Result<AuthResponseDto>.Failure("Invalid credentials");
        
        if (!user.IsActive)
            return Result<AuthResponseDto>.Failure("Account is deactivated");
        
        // Generate JWT token
        var token = await _jwtService.GenerateTokenAsync(user);
        
        // Get user roles
        var roles = await _authService.GetUserRolesAsync(user);
        
        return Result<AuthResponseDto>.Success(new AuthResponseDto
        {
            Token = token.AccessToken,
            RefreshToken = token.RefreshToken,
            UserId = user.Id,
            Email = user.Email,
            Roles = [.. roles],
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
            : Result.Failure(string.Join("; ", result.Errors.Select(e => e.Description)));
    }
}