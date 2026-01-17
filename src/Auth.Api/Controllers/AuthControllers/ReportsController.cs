using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ReportsController : ControllerBase
{
    [HttpGet("financial")]
    [Authorize(Policy = "CanViewReports")]
    public IActionResult GetFinancialReport()
    {
        return Ok(new { Report = "Financial Report Data" });
    }
    
    [HttpGet("confidential")]
    [Authorize(Policy = "AdminCanDeleteUsers")]
    public IActionResult GetConfidentialReport()
    {
        return Ok(new { Report = "Confidential Report Data" });
    }
    
    [HttpGet("it-department")]
    [Authorize(Policy = "ITDepartmentOnly")]
    public IActionResult GetITDepartmentReport()
    {
        return Ok(new { Report = "IT Department Report" });
    }
    
    [HttpGet("senior-only")]
    [Authorize(Policy = "MinimumAge21")]
    public IActionResult GetSeniorReport()
    {
        return Ok(new { Report = "Senior Report" });
    }
    
    [HttpGet("senior-it-manager")]
    [Authorize(Policy = "SeniorITManager")]
    public IActionResult GetSeniorITManagerReport()
    {
        return Ok(new { Report = "Senior IT Manager Report" });
    }
    
    // Multiple policies
    [HttpGet("complex-report")]
    [Authorize(Policy = "RequireManager")]
    [Authorize(Policy = "CanViewReports")]
    [Authorize(Policy = "ITDepartmentOnly")]
    public IActionResult GetComplexReport()
    {
        return Ok(new { Report = "Complex Report Data" });
    }
}