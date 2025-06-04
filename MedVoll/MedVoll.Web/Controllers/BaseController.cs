using MedVoll.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace MedVoll.Web.Controllers
{
    public class BaseController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;

        //CONSTRUTOR DA CLASSE
        public BaseController(SignInManager<IdentityUser> signInManager)
        {
            _signInManager = signInManager;
        }

        //MÉTODO EXECUTADO SEMPRE QUE UMA REQUISIÇÃO É FEITA AOS CONTROLLERS
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            //SE FOR UMA REQUISIÇÃO DE UM IP DIFERENTE DO IP DA SESSÃO, REDIRECIONA
            //PARA LOGIN - JÁ DESLOGADO
            if (!CheckSessionSecurity())
            {
                context.Result = new RedirectResult("./Login");
            }

            ViewData["Especialidades"] = GetEspecialidades();
            //MOSTRA NA VIEW O DADO DA VARIÁVEL DE SESSÃO VollMedCard
            ViewData["VollMedCard"] = HttpContext.Session.GetString("VollMedCard");
            base.OnActionExecuting(context);
        }

        private List<Especialidade> GetEspecialidades()
        {
            var especialidades = (Especialidade[])Enum.GetValues(typeof(Especialidade));
            return especialidades.ToList();
        }

        //MÉTODO QUE COMPARA O IP ATUAL COM O IP DA SESSÃO - PARA EVITAR ATAQUE DE IPs
        //EXTERNOS À SESSÃO COM COOKIES SEQUESTRADOS
        //MÉTODO USADO EM OnActionExecuting
        private bool CheckSessionSecurity()
        {
            var currentIp = HttpContext.Connection.RemoteIpAddress.ToString();
            var sessionIp = HttpContext.Session.GetString("IpAddress");

            if (sessionIp != null && sessionIp != currentIp)
            {
                HttpContext.Session.Clear();
                _signInManager.SignOutAsync();
                return false;
            }

            HttpContext.Session.SetString("IpAddress", currentIp);
            return true;
        }


    }
}
