using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebServer.Models;
using WebServer.Models.WebServerDB;

namespace WebServer.Services
{
    public class SiteService
    {
        private readonly WebServerDBContext _WebServerDBContext;
        private readonly IHttpContextAccessor _context;
        private readonly IConfiguration _configuration;

        public SiteService(WebServerDBContext WebServerDBContext,
            IHttpContextAccessor context,
            IConfiguration configuration)
        {
            _WebServerDBContext = WebServerDBContext;
            _context = context;
            _configuration = configuration;
        }

        /// <summary>
        /// 字串加密
        /// </summary>
        /// <param name="input"></param>
        /// <returns>SHA512</returns>
        public string EncoderSHA512(string input)
        {
            string salt = _configuration.GetValue<string>("Salt");
            var message = Encoding.UTF8.GetBytes(salt + input);
            using (var alg = SHA512.Create())
            {
                string output = string.Empty;

                var hashValue = alg.ComputeHash(message);
                foreach (byte x in hashValue)
                {
                    output += String.Format("{0:x2}", x);
                }
                return output;
            }
        }

        /// <summary>
        /// 記錄使用者資訊到Session
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public async Task SetUserProfile(string id)
        {
            await Task.Yield();
            var user = _WebServerDBContext.User.Find(id);
            _context?.HttpContext?.Session.SetString("CurrentUser", JsonSerializer.Serialize(new UserProfileModel
            {
                ID = user?.ID,
                Account = user?.Account,
                DisplayName = user?.Name,
                Email = user?.Email,
            }));
        }

        /// <summary>
        /// 從Session讀取使用者資訊
        /// </summary>
        /// <returns>UserProfile</returns>
        public async Task<UserProfileModel?> GetUserProfile()
        {
            await Task.Yield();
            var UserSessionString = _context?.HttpContext?.Session.GetString("CurrentUser");
            if (string.IsNullOrEmpty(UserSessionString))
            {
                return null;
            }
            return JsonSerializer.Deserialize<UserProfileModel>(UserSessionString);
        }
    }
}