using Auth.Application.Features.Auth.Commands.Requests;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers.AuthControllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;
    
    public AuthController(IMediator mediator)
    {
        _mediator = mediator;
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterCommand command)
    {
        var result = await _mediator.Send(command);
        
        if (result == null)
            return BadRequest("Registration failed");
        
        return Ok(result);
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginCommand command)
    {
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
            return Unauthorized(result);
        
        return Ok(result);
    }
    
    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(RefreshTokenCommand command)
    {
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
            return Unauthorized(result);
        
        return Ok(result);
    }
}