using System.Threading.Tasks;
using Auth.Domain.Entities.Auth;
using Microsoft.AspNetCore.Identity;

namespace Auth.Infrastructure.Persistence
{
    public static class SeedData
    {
        public static async Task SeedRolesAndUsersAsync(RoleManager<Role> roleManager, UserManager<User> userManager)
        {
            const string adminRole = "Admin";
            const string description = "Administrator role with full permissions";
            if (!await roleManager.RoleExistsAsync(adminRole))
                await roleManager.CreateAsync(new Role { Name = adminRole, Description = description });

            var adminEmail = "admin.application@gmail.com.com";
            var FirstName = "Application";
            var LastName = "Admin";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                adminUser = new User { UserName = "Applicationadmin", Email = adminEmail, EmailConfirmed = true, FirstName = FirstName, LastName = LastName };
                await userManager.CreateAsync(adminUser, "Admin#12345");
                await userManager.AddToRoleAsync(adminUser, adminRole);
            }
        }
    }
}