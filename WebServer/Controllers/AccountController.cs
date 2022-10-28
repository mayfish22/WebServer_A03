using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using WebServer.Models;
using WebServer.Models.WebServerDB;
using WebServer.Services;

namespace WebServer.Controllers
{
    public class AccountController : Controller
    {
        private readonly WebServerDBContext _WebServerDBContext;
        private readonly SiteService _SiteService;

        public AccountController(WebServerDBContext WebServerDBContext
            , SiteService SiteService)
        {
            _WebServerDBContext = WebServerDBContext;
            _SiteService = SiteService;
        }

        [HttpGet]
        public async Task<IActionResult> Signin(string returnUrl)
        {
            await Task.Yield();
            var model = new SigninViewModel
            {
                //登入後要轉跳的頁面
                ReturnUrl = returnUrl,
            };
            return View(model);
        }

        [HttpPost]
        //防止 CSRF (Cross-Site Request Forgery) 跨站偽造請求的攻擊
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Signin(SigninViewModel model)
        {
            try
            {
                //檢查帳號密碼是否正確
                //通常帳號會忽略大小寫
                if (string.IsNullOrEmpty(model.Account))
                {
                    throw new Exception("請輸入帳號");
                }
                if (string.IsNullOrEmpty(model.Password))
                {
                    throw new Exception("請輸入密碼");
                }

                //允許 Account 或 Email 登入
                var query = from s in _WebServerDBContext.User
                            where (s.Account.ToUpper() == model.Account.Trim().ToUpper()
                                 || s.Email.ToUpper() == model.Account.Trim().ToUpper())
                                && s.Password == _SiteService.EncoderSHA512(model.Password)
                            select s;

                if (query == null || !query.Any())
                    throw new Exception("帳號或密碼錯誤");

                if (query.FirstOrDefault()?.IsEnabled == 0)
                    throw new Exception("帳號停用");

                // 設定 Cookie
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, model.Account.Trim().ToUpper()),
                };
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(principal);

                //沒有指定返回的頁面就導向 /Home/Index
                if (string.IsNullOrEmpty(model.ReturnUrl))
                    return RedirectToAction("Index", "Home");
                else
                    return Redirect(model.ReturnUrl);
            }
            catch (Exception e)
            {
                //錯誤訊息
                ModelState.AddModelError(nameof(SigninViewModel.ErrorMessage), e.Message);
                return View(nameof(Signin), model);
            }
        }

        [HttpGet, HttpPost]
        public async Task<IActionResult> Signout([FromQuery] string ReturnUrl)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            foreach (var cookie in HttpContext.Request.Cookies)
            {
                Response.Cookies.Delete(cookie.Key);
            }
            HttpContext.Session.Remove("CurrentUser");
            HttpContext.Session.Clear();
            //導頁至 Account/Signin
            return RedirectToAction("Signin", "Account", new
            {
                returnUrl = ReturnUrl
            });
        }

        [HttpGet]
        public async Task<IActionResult> Signup()
        {
            await Task.Yield();
            var model = new SignupViewModel();
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Signup(SignupViewModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values.Where(s => s.Errors.Any()).Select(s => s);
                    throw new Exception(errors.First().Errors.First().ErrorMessage);
                }
                if(model.User != null)
                {
                    model.User.ID = Guid.NewGuid().ToString().ToUpper();
                    model.User.Account = model.User.Account.Trim();
                    model.User.Password = _SiteService.EncoderSHA512(model.User.Password);
                    model.User.Name = model.User.Name.Trim();
                    model.User.Email = model.User.Email.Trim().ToUpper();
                    model.User.IsEnabled = 1;

                    await _WebServerDBContext.User.AddAsync(model.User);
                    await _WebServerDBContext.SaveChangesAsync();
                }
            }
            catch (Exception e)
            {
                ModelState.AddModelError(nameof(SignupViewModel.ErrorMessage), e.Message);
                return View(model);
            }
            //返回登入頁, 並自動代入所註冊的帳號
            return View(nameof(Signin), new SigninViewModel
            {
                Account = model.User?.Account,
            });
        }
    }
}