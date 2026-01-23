using Auth.Application.Features.Auth.Commands.Requests;
using Auth.Application.Features.Auth.Queries.Requests;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Api.Controllers.AuthControllers;

[ApiController]
[Route("api/[controller]")]
public class PermissionController : ControllerBase
{

    private readonly IMediator _mediator;

    public PermissionController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [HttpPost("permission/create")]
    public async Task<IActionResult> CreatePermission([FromBody] CreatePermissionCommand command)
    {
        var result = await _mediator.Send(command);
        if (result == null)
            return BadRequest("Permission creation failed");

        return Ok(result);
    }

    [HttpPost("user/{userId}/assign-permissions")]
    public async Task<IActionResult> AssignPermissionsToUser(Guid userId, [FromBody] IEnumerable<Guid> permissions)
    {
        var command = new AssignPermissionsToUserCommand
        {
            UserId = userId,
            Permissions = permissions
        };

        var result = await _mediator.Send(command);
        if (!result.Succeeded)
            return BadRequest("Assigning permissions failed");

        return Ok(result);
    }

    [HttpPost("user/{userId}/remove-permissions")]
    public async Task<IActionResult> RemovePermissionsFromUser(Guid userId, [FromBody] IEnumerable<Guid> permissions)
    {
        var command = new RemovePermissionsFromUserCommand
        {
            UserId = userId,
            Permissions = permissions
        };

        var result = await _mediator.Send(command);
        if (!result.Succeeded)
            return BadRequest("Removing permissions failed");

        return Ok(result);
    }

    [HttpGet("user/{userId}/permissions")]
    public async Task<IActionResult> GetUserPermissions(Guid userId)
    {
        var query = new GetUserPermissionQuery
        {
            UserId = userId
        };

        var result = await _mediator.Send(query);
        if (result == null)
            return NotFound("User permissions not found");

        return Ok(result);
    }
    
    [HttpGet("role/{roleName}/permissions")]
    public async Task<IActionResult> GetRolePermissions(string roleName)
    {
        var query = new GetRolePermissionQuery
        {
            RoleName = roleName
        };

        var result = await _mediator.Send(query);
        if (result == null)
            return NotFound("Role permissions not found");

        return Ok(result);
    }

    [HttpGet("user/{userId}/has-permission/{permissionId}")]
    public async Task<IActionResult> UserHasPermission(Guid userId, Guid permissionId)
    {
        var query = new UserHasPermissionQuery
        {
            UserId = userId,
            PermissionId = permissionId
        };

        var result = await _mediator.Send(query);
        return Ok(result);
    }

    [HttpGet("permissions/all")]
    public async Task<IActionResult> GetAllPermissions()
    {
        var query = new GetAllPermissionsQuery();
        var result = await _mediator.Send(query);
        return Ok(result);
    }
}