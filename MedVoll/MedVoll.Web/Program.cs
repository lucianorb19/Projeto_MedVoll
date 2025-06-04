using MedVoll.Web.Data;
using MedVoll.Web.Filters;
using MedVoll.Web.Interfaces;
using MedVoll.Web.Repositories;
using MedVoll.Web.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<ExceptionHandlerFilter>();

// Add services to the container.
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add<ExceptionHandlerFilter>();
});

var connectionString = builder.Configuration.GetConnectionString("SqliteConnection");
builder.Services.AddDbContext<ApplicationDbContext>(x => x.UseSqlite(connectionString));

//.AddRoles<IdentityRole>() - APLICA��O CONSEGUE ADICIONAR PAP�IS AOS USU�RIOS
builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

//CONFIRMA��O DE E-MAIL PARA CADASTRAR USU�RIO
//EM TEORIA, O USU�RIO PRECISARIA ACESSAR SUA CAIXA DE ENTRADA PARA CONFIRMAR O E-MAIL E CADASTRAR
//MAS COMO A APLIA��O N�O TEM UM EMISSOR DE E-MAIL, ELA MESMA OFERECE A OP��O DE CONFIRMAR
builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedEmail = true; // Exigir e-mails confirmados para login
    options.SignIn.RequireConfirmedPhoneNumber = false; // N�o exigir confirma��o de n�mero de telefone
});

//BLOQUEIO DE TENTATIVA DE ACESSO POR 2 MINUTOS AP�S ERRAR A SENHA 3X
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Lockout.AllowedForNewUsers = true;//V�LIDO TAMB�M PARA NOVOS USU�RIOS
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(2);
    options.Lockout.MaxFailedAccessAttempts = 3;
});

//CONFIGURA��ES ADICIONAIS PARA A SENHA DE LOGIN
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true; // Exigir pelo menos um n�mero
    options.Password.RequireLowercase = true; // Exigir pelo menos uma letra min�scula
    options.Password.RequireUppercase = true; // Exigir pelo menos uma letra mai�scula
    options.Password.RequireNonAlphanumeric = true; // Exigir caracteres especiais
    options.Password.RequiredLength = 8; // Tamanho m�nimo da senha
});

//CONFIGURA��ES ADICIONAIS PARA O COMPORTAMENTO DA SESS�O / COOKIE
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Account/Login"; // Redireciona para login se n�o autenticado
    options.LogoutPath = "/Identity/Account/Logout"; // Caminho para logout
    options.AccessDeniedPath = "/Identity/Account/AccessDenied"; // Caminho para acesso negado
    options.ExpireTimeSpan = TimeSpan.FromMinutes(2); // Tempo de expira��o da sess�o em caso de inatividade
    options.SlidingExpiration = true; // Renova o cookie sempre que houver atividade

    options.Cookie.HttpOnly = true; // Impede acesso via JavaScript
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Exige HTTPS
    options.Cookie.SameSite = SameSiteMode.Strict; // Restringe envio desse cookie para outro site fora da aplica��o
});

builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedEmail = true; // Exigir e-mails confirmados para login
    options.SignIn.RequireConfirmedPhoneNumber = false; // N�o exigir confirma��o de n�mero de telefone
});

builder.Services.AddTransient<IMedicoRepository, MedicoRepository>();
builder.Services.AddTransient<IConsultaRepository, ConsultaRepository>();
builder.Services.AddTransient<IMedicoService, MedicoService>();
builder.Services.AddTransient<IConsultaService, ConsultaService>();

//MIDDLEWARE CONTRA ATAQUES CSRF
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "VollMed.AntiForgery"; // Nome personalizado do cookie
    options.Cookie.HttpOnly = true; // Evitar acesso via JavaScript
    options.HeaderName = "X-CSRF-TOKEN"; // Cabe�alho personalizado para APIs
});

//CONTROLE DE AUTORIZA��O - [Authorize] NO IN�CIO DA CLASSE
builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/erro/500");
    app.UseStatusCodePagesWithReExecute("/erro/{0}");
}

app.UseStaticFiles();

app.UseRouting();

//USO DE UM MIDDLEWARE DE AUTENTICA��O NO PIPELINE DE REQUISI��ES
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

//HABILITA AS P�GINAS DE LOGIN E CADASTRO - FEITO NO SCAFOLDING
//E HABILITA O USO DESSES RECURSOS NOS ARQUIVOS EST�TICOS DO ASP.NET CORE IDENTITY - CSS, JS
app.MapRazorPages().WithStaticAssets();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        await IdentitySeeder.SeedUsersAsync(services);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erro ao executar o Seeder: {ex.Message}");
    }
}

app.Run();
