using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Twitter;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Blazor.Services;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Threading.Tasks;

namespace BlazingPizza.Server
{
    [ApiController]
    public class UserController : Controller
    {
        private static UserInfo LoggedOutUser = new UserInfo { IsAuthenticated = false };
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(SignInManager<IdentityUser> singInManager, UserManager<IdentityUser> userManager)
        {
            _signInManager = singInManager;
            _userManager = userManager;
        }

        [HttpGet("user")]
        public UserInfo GetUser()
        {
            return User.Identity.IsAuthenticated
                ? new UserInfo { Name = User.Identity.Name, IsAuthenticated = true }
                : LoggedOutUser;
        }

        [HttpGet("user/signin")]
        public async Task SignIn(string redirectUri)
        {
            //сохраним uri чтобы редиректнуть на него после
            var signInCallbackUri = Url.Action(nameof(SignInCallback), "user", new { redirectUri });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties(TwitterDefaults.AuthenticationScheme, signInCallbackUri);

            await HttpContext.ChallengeAsync(TwitterDefaults.AuthenticationScheme, properties);
        }

        [HttpGet("user/signincallback")]
        public async Task<IActionResult> SignInCallback(string redirectUri)
        {
            if (string.IsNullOrEmpty(redirectUri) || !Url.IsLocalUrl(redirectUri))
            {
                redirectUri = "/";
            }
            //Получаем внешнюю информацию для логина
            var info = await _signInManager.GetExternalLoginInfoAsync();
            //Логинимся
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (!result.Succeeded)
            {
                //Логин неуспешный потому что нет юзера, создаем его
                var user = new IdentityUser(info.Principal.Identity.Name);
                await _userManager.CreateAsync(user);
                await _userManager.AddLoginAsync(user, info);
                //Логинимся
                await _signInManager.SignInAsync(user, isPersistent: false);
            }
            return Redirect(redirectUri);
        }

        [HttpGet("user/signout")]
        public async Task<IActionResult> SignOut()
        {
            await _signInManager.SignOutAsync();
            return Redirect("~/");
        }
    }
}
