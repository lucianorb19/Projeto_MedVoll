using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

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
            
            // CRIA O PAPÉL DE User, CASO AINDA NÃO EXISTA
            const string userRole = "User";
            if (!await roleManager.RoleExistsAsync(userRole))
            {
                await roleManager.CreateAsync(new IdentityRole(userRole));
            }

            // COM A FUNÇÃO CreateUserAsync - CRIA DOIS USUÁRIOS ESPECÍFICOS
            await CreateUserAsync(userManager, "alice@smith.com", "Password@123", userRole);
            await CreateUserAsync(userManager, "bob@smith.com", "Password@123", userRole);

            //CRIA O PAPEL Admin CASO AINDA NÃO EXISTA
            const string adminRole = "Admin";
            if(! await roleManager.RoleExistsAsync(adminRole))
            {
                await roleManager.CreateAsync(new IdentityRole(adminRole));
            }

            //TORNA ALICE ADMIN DA APLICAÇÃO
            IdentityUser? alice = await userManager.FindByEmailAsync("alice@smith.com");
            IList<IdentityUser> admins = await userManager.GetUsersInRoleAsync(adminRole);
            if (!admins.Any(a => a.Email == alice.Email))
            {
                await userManager.AddToRoleAsync(alice, adminRole);
            }

            IdentityUser? bob = await userManager.FindByEmailAsync("bob@smith.com");

            //CLAIMS PARA ALICE
            IList<Claim> userClaims = await userManager.GetClaimsAsync(alice);
            await userManager.RemoveClaimsAsync(alice, userClaims);
            await userManager.AddClaimAsync(alice, new Claim("FullName", "Alice Smith"));
            await userManager.AddClaimAsync(alice, new Claim("Role", "Admin"));
            //CLAIMS PARA BOB
            userClaims = await userManager.GetClaimsAsync(bob);
            await userManager.RemoveClaimsAsync(bob, userClaims);
            await userManager.AddClaimAsync(bob, new Claim("FullName", "Bob Smith"));
        

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
