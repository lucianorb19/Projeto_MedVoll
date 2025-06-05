# Projeto_MedVoll
Aplicação WEB para a clínica médica MedVoll. O projeto simula casos de uso de diversas implementações de segurança.  
Desenvolvido com ASP.NET Core

## DOWNLOADS NECESSÁRIOS
* Visual Studio 2022 (Com ASP.NET);
* Postman;
* Visual Stuido Code;
* DB Browser for SQLite;
* Projeto inicial: [baixar](https://github.com/alura-cursos/4320-seguranca-aspnetcore)

## IMPLEMENTAÇÕES DE SEGURANÇA TRATADAS
1. Proteções contra CSRF - _CROSS-SITE REQUEST FORGERY_;
1. Controle de autorização: página públicas e páginas restritas a usuários;
1. Confirmação de e-mail para cadastro;
1. Bloqueio temporário de acesso após erro de senha;
1. Configurações do Identity - _Password_ e _Cookies_ ;
1. Ataque de sessão: como evitar usando reautenticação transparente e comparação de IPs;
1. Validação de dados com _Data Annotations_ ;
1. Proteções contra XSS (_Cross-Site Scripting_) e _Sniffing_ de MIME Type;
1. Restrições de acesso utilizando _User Roles_ (Papéis do Usuário);
1. Restrições de acesso utilizando _User Claims_ ;

## CONFIGURAÇÕES INICIAIS
Instalar gerenciador de BD do .NET - Na pasta MedVoll.Web, pelo CMD  
```dotnet tool install --global dotnet-ef```

Aplicar as migrations iniciais do projeto -Pelo CMD, na pasta MedVoll.Web  
```dotnet ef database update```

Com o projeto aberto no Visual Strudio - Instalar Identity - Pelo Nuget  
Na interface do Visual Studio -> Ferramentas -> Gerenciador de Pacotes Nuget-> Gerenciar Pacotes  
Nome: Microsoft.AspNetCore.Identity.EntityFrameworkCore (v. 9.0.0)

Alterar classe ApplicationDbContext para herdar de IdentityDbContext  
```public class ApplicationDbContext : IdentityDbContext```

Scaffolding ao ASP.NETCoreIdentity - Criar a estrutura necessária para usar o identity na aplicação (nas views Account/Login e Account/Register)  
* Clique com o botão direito no projeto MedVoll.Web no Solution Explorer.
* Escolha o menu: Add > Add New Scaffolded Item.
* Na lista, selecione Identity.
* Marque os arquivos necessários:
    * Account\Login
    * Account\Register
* No campo DbContext class, selecione:ApplicationDbContext (MedVoll.Web.Data).

Gerar migração para o esquema do ASP.NET Core Identity - Pelo CMD, na pasta MedVoll.Web  
```dotnet ef migrations add CreateIdentitySchema```

Aplicar migração ao BD  
```dotnet ef database update```

*Para consultar o banco de dados da aplicação  
Botão direito em vollmed.db -> abrir com -> DB Browser fo SQLite

## 
## 
## 
## 
## 
## 
## 
## 
## 
