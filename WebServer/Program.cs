using Microsoft.EntityFrameworkCore;
using WebServer.Extensions;
using WebServer.Models.WebServerDB;
using WebServer.Services;

namespace WebServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews();

            //設定連線字串
            builder.Services.AddDbContext<WebServerDBContext>(options =>
            {
                options.UseSqlite(builder.Configuration.GetConnectionString("WebServerDB"));
            });

            // 使用 Session
            builder.Services.AddDistributedMemoryCache();

            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(60);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });

            // 使用 Cookie
            builder.Services
                .AddAuthentication(Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    //存取被拒轉跳頁面
                    options.AccessDeniedPath = new PathString("/Account/Signin");
                    //登入頁
                    options.LoginPath = new PathString("/Account/Signin");
                    //登出頁
                    options.LogoutPath = new PathString("/Account/Signout");
                });

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddScoped<SiteService>();
            builder.Services.AddScoped<ValidatorService>();

            var app = builder.Build();

            ServiceActivator.Configure(app.Services);

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();//驗證

            app.UseAuthorization();//授權 

            app.UseSession();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}