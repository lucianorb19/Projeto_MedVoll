using Microsoft.AspNetCore.Identity;

namespace MedVoll.Web.Data
{
    public class IdentitySeeder
    {
        //MÉTODO QUE CRIA DOIS USUÁRIOS DE PAPEL User
        public static async Task SeedUsersAsync(IServiceProvider serviceProvider)
        {
            //OBJETOS UserManager E RoleManager - GESTÃO DE USUÁRIOS E PAPÉIS
            var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            
            // Verifica e cria a função "User", se necessário
            // CRIA O PAPÉL DE User, CASO AINDA NÃO EXISTA
            const string userRole = "User";
            if (!await roleManager.RoleExistsAsync(userRole))
            {
                await roleManager.CreateAsync(new IdentityRole(userRole));
            }

            // COM A FUNÇÃO CreateUserAsync - CRIA DOIS USUÁRIOS ESPECÍFICOS
            await CreateUserAsync(userManager, "alice@smith.com", "Password@123", userRole);
            await CreateUserAsync(userManager, "bob@smith.com", "Password@123", userRole);
        }

        //MÉTODO QUE CRIA USUÁRIOS-DADO O OBJETO UserManager, EMAIL, SENHA E PAPÉL
        private static async Task CreateUserAsync(UserManager<IdentityUser> userManager, string email, string password, string role)
        {
            // SE O USUÁRIO JÁ EXISTE (VERIFICADO PELO E-MAIL) NÃO CRIA
            if (await userManager.FindByEmailAsync(email) != null)
            {
                return;
            }

            //SE NÃO EXISTE..
            var user = new IdentityUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true // Para evitar a necessidade de confirmação de email
            };
            // Cria o usuário
            var result = await userManager.CreateAsync(user, password);
            if (result.Succeeded)
            {
                // Atribui a função ao usuário
                await userManager.AddToRoleAsync(user, role);
            }
            else
            {
                throw new Exception($"Erro ao criar usuário {email}: {string.Join(", ", result.Errors)}");
            }
        }
    }
}
