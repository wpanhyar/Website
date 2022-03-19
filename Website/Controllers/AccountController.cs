using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Website.EFModel;
using Website.Models;
using Website.Providers;
using Website.Results;
using System.Web.Http.Cors;
using System.Linq;
using System.Data.Entity;

namespace Website.Controllers
{
    [Authorize]
    [RoutePrefix("api/Account")]
    [EnableCors(origins: "*", headers: "*", methods: "*")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;
        ApplicationDbContext context;

        public AccountController()
        {
            context = new ApplicationDbContext();
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // GET api/Account/UserInfo
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserInfo")]
        public UserInfoViewModel GetUserInfo()
        {
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            return new UserInfoViewModel
            {
                Email = User.Identity.GetUserName(),
                HasRegistered = externalLogin == null,
                LoginProvider = externalLogin != null ? externalLogin.LoginProvider : null
            };
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            IdentityUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            if (user == null)
            {
                return null;
            }

            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();

            foreach (IdentityUserLogin linkedAccount in user.Logins)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = linkedAccount.LoginProvider,
                    ProviderKey = linkedAccount.ProviderKey
                });
            }

            if (user.PasswordHash != null)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = LocalLoginProvider,
                    ProviderKey = user.UserName,
                });
            }

            return new ManageInfoViewModel
            {
                LocalLoginProvider = LocalLoginProvider,
                Email = user.UserName,
                Logins = logins,
                ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
            };
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);
            
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        [AllowAnonymous]
        public async Task<HttpResponseModel> SetPassword(SetPasswordBindingModel model)
        {
            try
            {
                string Message = string.Empty;
                if (!ModelState.IsValid)
                {
                    Message = string.Join(" | ", ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage));
                    return new HttpResponseModel { Status = 400, Message = Message };
                }

                IdentityResult result = await UserManager.AddPasswordAsync(model.UserID, model.NewPassword);
                if (!result.Succeeded)
                {
                    return new HttpResponseModel { Status = 400, Message = string.Join(" | ", result.Errors ) };
                }

                using (context = new ApplicationDbContext())
                {
                    var user = context.Users.SingleOrDefault(b => b.Id == model.UserID);
                    if (user != null)
                    {
                        user.IsSetPassword = true;
                        context.SaveChanges();
                    }
                }

                return new HttpResponseModel { Status = 200, Message = "Password created successfully" };
            }
            catch (Exception ex)
            {
                Log.LogException(ex);
                return new HttpResponseModel { Status = 400, Message = ex.Message };
            }
        }

        // POST api/Account/VerifyEmail
        [Route("VerifyEmail")]
        [AllowAnonymous]
        public async Task<HttpResponseModel> VerifyEmail(VerifyEmailConfirmation model)
        {
            string Message = string.Empty;
            if (!ModelState.IsValid)
            {
                Message = string.Join(" | ", ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage));
                return new HttpResponseModel { Status = 400, Message = Message };
            }

            var user = context.Users.Where(x => x.Id == model.UserId).FirstOrDefault();
            var emailConfirmationResult = await UserManager.ConfirmEmailAsync(model.UserId, model.Token);
            if (emailConfirmationResult.Succeeded)
            {
                Message = "Email is confirmed";
            }

            return new HttpResponseModel { Status = 200, Message = Message, Data = new { IsSetPassword = user.IsSetPassword, Email = user.Email } };
        }

        [Route("ForgotPassword")]
        [AllowAnonymous]
        public async Task<HttpResponseModel> ForgotPassword(ForgotPasswordModel forgotPasswordModel)
        {
            try
            {
                if (!ModelState.IsValid)
                    return new HttpResponseModel { Status = 500, Message = "Something went wrong, please try again later" };

                var user = await UserManager.FindByEmailAsync(forgotPasswordModel.Email);
                if (user == null)
                    return new HttpResponseModel { Status = 400, Message = "User is not available" };

                var token = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                List<WordsToReplace> wtr = new List<WordsToReplace> {
                    new WordsToReplace { FileWord = "{Name}", Replacement = user.Firstname },
                    new WordsToReplace { FileWord = "{URL}", Replacement = HttpContext.Current.Request.Url.Host + @"/ResetPassword?userId="+ user.Id + "&token="+token },
                    new WordsToReplace { FileWord = "{Year}", Replacement = DateTime.Now.Year.ToString() }
                };

                var htmlBody = ReadFile.UpdateHtmlFile("Forgot-Password-Email-Template.html", wtr);
                SmtpProvider.SendEmail(user.Email, "Reset your account password", htmlBody);

                return new HttpResponseModel { Status = 200, Message = "Password reset email sent successfully" };
            }
            catch (Exception ex)
            {
                Log.LogException(ex);
                return new HttpResponseModel { Status = 200, Message = ex.Message };
            }
            
        }

        [Route("ResetPassword")]
        [AllowAnonymous]
        public async Task<HttpResponseModel> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            try
            {
                if (!ModelState.IsValid)
                    return new HttpResponseModel { Status = 500, Message = "Something went wrong, please try again later" };

                var user = await UserManager.FindByIdAsync(resetPasswordModel.UserId);
                if (user == null)
                    return new HttpResponseModel { Status = 400, Message = "User is not available" };

                var resetPassResult = await UserManager.ResetPasswordAsync(user.Id, resetPasswordModel.Token, resetPasswordModel.Password);
                if (!resetPassResult.Succeeded)
                {
                    return new HttpResponseModel { Status = 400, Message = "Password and confirm password do not match" };
                }
                return new HttpResponseModel { Status = 200, Message = "Password reset successfully" };
            }
            catch (Exception ex)
            {
                Log.LogException(ex);
                return new HttpResponseModel { Status = 200, Message = ex.Message };
            }
            
        }


        // POST api/Account/AddExternalLogin
        [Route("AddExternalLogin")]
        public async Task<IHttpActionResult> AddExternalLogin(AddExternalLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            AuthenticationTicket ticket = AccessTokenFormat.Unprotect(model.ExternalAccessToken);

            if (ticket == null || ticket.Identity == null || (ticket.Properties != null
                && ticket.Properties.ExpiresUtc.HasValue
                && ticket.Properties.ExpiresUtc.Value < DateTimeOffset.UtcNow))
            {
                return BadRequest("External login failure.");
            }

            ExternalLoginData externalData = ExternalLoginData.FromIdentity(ticket.Identity);

            if (externalData == null)
            {
                return BadRequest("The external login is already associated with an account.");
            }

            IdentityResult result = await UserManager.AddLoginAsync(User.Identity.GetUserId(),
                new UserLoginInfo(externalData.LoginProvider, externalData.ProviderKey));

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/RemoveLogin
        [Route("RemoveLogin")]
        public async Task<IHttpActionResult> RemoveLogin(RemoveLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result;

            if (model.LoginProvider == LocalLoginProvider)
            {
                result = await UserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(),
                    new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            if (error != null)
            {
                return Redirect(Url.Content("~/") + "#error=" + Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                
                 ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName);
                Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);
            }
            else
            {
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                ClaimsIdentity identity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
                Authentication.SignIn(identity);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogins?returnUrl=%2F&generateState=true
        [AllowAnonymous]
        [Route("ExternalLogins")]
        public IEnumerable<ExternalLoginViewModel> GetExternalLogins(string returnUrl, bool generateState = false)
        {
            IEnumerable<AuthenticationDescription> descriptions = Authentication.GetExternalAuthenticationTypes();
            List<ExternalLoginViewModel> logins = new List<ExternalLoginViewModel>();

            string state;

            if (generateState)
            {
                const int strengthInBits = 256;
                state = RandomOAuthStateGenerator.Generate(strengthInBits);
            }
            else
            {
                state = null;
            }

            foreach (AuthenticationDescription description in descriptions)
            {
                ExternalLoginViewModel login = new ExternalLoginViewModel
                {
                    Name = description.Caption,
                    Url = Url.Route("ExternalLogin", new
                    {
                        provider = description.AuthenticationType,
                        response_type = "token",
                        client_id = Startup.PublicClientId,
                        redirect_uri = new Uri(Request.RequestUri, returnUrl).AbsoluteUri,
                        state = state
                    }),
                    State = state
                };
                logins.Add(login);
            }

            return logins;
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [Route("Register")]
        public async Task<HttpResponseModel> Register(RegisterBindingModel model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return new HttpResponseModel { Status = 400, Message = "Please fill appropriate fields"};
                }
                if (UserManager.FindByEmail(model.Email) != null)
                {
                    return new HttpResponseModel { Status = 400, Message = "User already exists" };
                }
                var user = new ApplicationUser()
                {
                    UserName = model.Email,
                    Email = model.Email,
                    Firstname = model.Firstname,
                    Lastname = model.Lastname,
                    CountryId = model.CountryID
                };
                IdentityResult result = await UserManager.CreateAsync(user);
                await SendConfirmation(new EmailConfirmationModel { UserID = user.Id });
                await this.UserManager.AddToRoleAsync(user.Id, model.UserRoles);

                if (!result.Succeeded)
                {
                    Log.LogString("Something went wrong, please try again later");
                    return new HttpResponseModel { Status = 500, Message = GetErrorResult(result).ToString() };
                }

                return new HttpResponseModel
                {
                    Status = 200,
                    Message = "Successfully created.",
                    Data = new
                    {
                        UserID = user.Id,
                        Email = user.Email
                    }
                };
            }
            catch (Exception ex)
            {
                Log.LogException(ex);
                return new HttpResponseModel { Status = 500, Message = ex.Message };
            }
        }

        [AllowAnonymous]
        [Route("SendEmailConfirmation")]
        public async Task<HttpResponseModel> SendConfirmation(EmailConfirmationModel model)
        {
            try
            {
                var user = await UserManager.FindByIdAsync(model.UserID);
                var confirmationToken = await UserManager.GenerateEmailConfirmationTokenAsync(model.UserID);

                List<WordsToReplace> wtr = new List<WordsToReplace> {
                    new WordsToReplace { FileWord = "{Name}", Replacement = user.Firstname },
                    new WordsToReplace { FileWord = "{URL}", Replacement = HttpContext.Current.Request.Url.Host + @"/SetPassword?userId="+ user.Id + "&token="+confirmationToken },
                    new WordsToReplace { FileWord = "{Year}", Replacement = DateTime.Now.Year.ToString() }
                };

                var htmlBody = ReadFile.UpdateHtmlFile("Confirm-Email-Template.html", wtr);
                SmtpProvider.SendEmail(user.Email, "Please Confirm you email and set your password", htmlBody);
            }
            catch (Exception ex)
            {
                Log.LogException(ex);
                return new HttpResponseModel { Status = 500, Message = ex.Message };
            }

            return new HttpResponseModel { Status = 200, Message = "Successfully email sent" };            
        }

        // POST api/Account/RegisterExternal
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var info = await Authentication.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return InternalServerError();
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await UserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result); 
            }
            return Ok();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        #endregion
    }
}
