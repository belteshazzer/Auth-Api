using System.Reflection;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Application.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationServices(
        this IServiceCollection services)
    {
        services.AddMediatR(cfg => 
            cfg.RegisterServicesFromAssembly(Assembly.GetExecutingAssembly()));

        services.AddAutoMapper(cfg => { }, Assembly.GetExecutingAssembly());
        
        return services;
    }
}