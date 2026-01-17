using Core.Application.Features.Users.Commands.AssignPermissions;
using Core.Application.Features.Users.Commands.AssignRoles;
using Core.Application.Features.Users.Queries.GetUserPermissions;
using Core.Application.Features.Users.Queries.GetUserRoles;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly IMediator _mediator;
    
    public UsersController(IMediator mediator)
    {
        _mediator = mediator;
    }
    
    [HttpPost("{userId}/permissions")]
    [Authorize(Policy = "AdminCanDeleteUsers")]
    public async Task<IActionResult> AssignPermissions(
        string userId, 
        [FromBody] string[] permissions)
    {
        var command = new AssignPermissionsCommand
        {
            UserId = userId,
            Permissions = permissions
        };
        
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
            return BadRequest(result);
        
        return Ok(result);
    }
    
    [HttpGet("{userId}/permissions")]
    [Authorize(Policy = "CanViewReports")]
    public async Task<IActionResult> GetUserPermissions(string userId)
    {
        var query = new GetUserPermissionsQuery { UserId = userId };
        var result = await _mediator.Send(query);
        
        return Ok(result);
    }
    
    [HttpPost("{userId}/roles")]
    [Authorize(Policy = "RequireAdmin")]
    public async Task<IActionResult> AssignRoles(
        string userId, 
        [FromBody] string[] roles)
    {
        var command = new AssignRolesCommand
        {
            UserId = userId,
            Roles = roles
        };
        
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
            return BadRequest(result);
        
        return Ok(result);
    }
    
    [HttpGet("{userId}/roles")]
    [Authorize(Policy = "RequireManager")]
    public async Task<IActionResult> GetUserRoles(string userId)
    {
        var query = new GetUserRolesQuery { UserId = userId };
        var result = await _mediator.Send(query);
        
        return Ok(result);
    }
}