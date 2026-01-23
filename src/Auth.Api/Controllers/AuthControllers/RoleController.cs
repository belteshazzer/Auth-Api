using Auth.Application.Features.Auth.Commands.Requests;
using Auth.Application.Features.Auth.Queries.Requests;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers.AuthControllers;

[ApiController]
[Route("api/[controller]")]
public class RoleController : ControllerBase
{
    private readonly IMediator _mediator;
    
    public RoleController(IMediator mediator)
    {
        _mediator = mediator;
    }
    
    [HttpGet("user/{userId}/roles")]
    public async Task<IActionResult> GetUserRoles(Guid userId)
    {
        var query = new GetUserRolesQuery { UserId = userId };
        var roles = await _mediator.Send(query);
        return Ok(roles);
    }
    
    [HttpGet("roles")]
    public async Task<IActionResult> GetAllRoles()
    {
        var query = new GetAllRolesQuery();
        var roles = await _mediator.Send(query);
        return Ok(roles);
    }
    
    [HttpGet("role/id/{roleId}")]
    public async Task<IActionResult> GetRoleById(Guid roleId)
    {
        var query = new GetRoleByIdQuery { RoleId = roleId };
        var role = await _mediator.Send(query);
        if (role == null)
            return NotFound();
        return Ok(role);
    }

    [HttpGet("role/name/{roleName}")]
    public async Task<IActionResult> GetRoleByName(string roleName)
    {
        var query = new GetRoleByNameQuery { RoleName = roleName };
        var role = await _mediator.Send(query);
        if (role == null)
            return NotFound();
        return Ok(role);
    }

    [HttpGet("user/{userId}/is-in-role/{roleName}")]
    public async Task<IActionResult> IsInRole(Guid userId, string roleName)
    {
        var query = new IsInRoleQuery { UserId = userId, RoleName = roleName };
        var isInRole = await _mediator.Send(query);
        return Ok(isInRole);
    }

    [HttpPost("role/create")]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleCommand command)
    {
        var result = await _mediator.Send(command);
        if (!result.Succeeded)
            return BadRequest(result);
        return Ok(result);
    }

    [HttpDelete("role/delete/{roleId}")]
    public async Task<IActionResult> DeleteRole(Guid roleId)
    {
        var command = new DeleteRoleCommand { RoleId = roleId };
        var result = await _mediator.Send(command);
        if (!result.Succeeded)
            return BadRequest(result);
        return Ok(result);
    }

    [HttpPost("user/{userId}/assign-roles")]
    public async Task<IActionResult> AssignRolesToUser(Guid userId, [FromBody] IEnumerable<string> roles)
    {
        var command = new AssignRolesToUserCommand { UserId = userId, Roles = roles };
        var result = await _mediator.Send(command);
        if (!result.Succeeded)
            return BadRequest(result);
        return Ok(result);
    }

    [HttpPost("user/{userId}/remove-roles")]
    public async Task<IActionResult> RemoveRolesFromUser(Guid userId, [FromBody] IEnumerable<string> roles)
    {
        var command = new RemoveRolesFromUserCommand { UserId = userId, Roles = roles };
        var result = await _mediator.Send(command);
        if (!result.Succeeded)
            return BadRequest(result);
        return Ok(result);
    }

}