using Core.Application.Common.Interfaces;
using Infrastructure.Identity.Authorization;
using Infrastructure.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Infrastructure.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructureServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Identity services
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IJwtService, JwtService>();
        
        // Authorization handlers
        services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, RoleWithPermissionAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, DepartmentAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, MinimumAgeAuthorizationHandler>();
        
        // Configure JWT
        services.Configure<JwtSettings>(configuration.GetSection("JwtSettings"));
        
        return services;
    }
    
    public static IServiceCollection AddIdentityAuthorizationPolicies(
        this IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            // Role-based policies
            options.AddPolicy("RequireAdmin", policy => 
                policy.RequireRole("Admin"));
            
            options.AddPolicy("RequireManager", policy => 
                policy.RequireRole("Admin", "Manager"));
            
            // Permission-based policies
            options.AddPolicy("CanViewReports", policy =>
                policy.Requirements.Add(new PermissionRequirement("ViewReports")));
            
            options.AddPolicy("CanEditContent", policy =>
                policy.Requirements.Add(new PermissionRequirement("EditContent")));
            
            options.AddPolicy("CanDeleteUsers", policy =>
                policy.Requirements.Add(new PermissionRequirement("DeleteUsers")));
            
            // Combined role and permission policies
            options.AddPolicy("AdminCanDeleteUsers", policy =>
            {
                policy.RequireRole("Admin");
                policy.Requirements.Add(new PermissionRequirement("DeleteUsers"));
            });
            
            // Department-based policies
            options.AddPolicy("ITDepartmentOnly", policy =>
                policy.Requirements.Add(new DepartmentRequirement("IT")));
            
            options.AddPolicy("HRDepartmentOnly", policy =>
                policy.Requirements.Add(new DepartmentRequirement("HR")));
            
            // Age-based policies
            options.AddPolicy("MinimumAge21", policy =>
                policy.Requirements.Add(new MinimumAgeRequirement(21)));
            
            // Custom composite policies
            options.AddPolicy("SeniorITManager", policy =>
            {
                policy.RequireRole("Manager");
                policy.Requirements.Add(new DepartmentRequirement("IT"));
                policy.Requirements.Add(new MinimumAgeRequirement(30));
                policy.Requirements.Add(new PermissionRequirement("ApproveBudget"));
            });
            
            // Dynamic policy - can be resolved at runtime
            options.AddPolicy("DynamicPermission", policy =>
                policy.Requirements.Add(new DynamicPermissionRequirement()));
        });
        
        return services;
    }
}