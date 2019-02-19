using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using LocalTheatreAssessmentLB.Models;
using System.Configuration;
using Microsoft.AspNet.Identity.EntityFramework;

namespace LocalTheatreAssessmentLB.Controllers
{
    /// <summary>   A controller for handling accounts. </summary>
    ///
    /// <remarks>   Lukas, 30.01.2019. </remarks>

    [Authorize]
    public class AccountController : Controller
    {

        /// <summary>   Manager for sign in. </summary>
        private ApplicationSignInManager _signInManager;

        /// <summary>   Manager for user. </summary>
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }

        /// <summary>   Constructor. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="userManager">      Manager for user. </param>
        /// <param name="signInManager">    Manager for sign in. </param>

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        /// <summary>   Gets or sets the manager for sign in. </summary>
        ///
        /// <value> The sign in manager. </value>

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        /// <summary>   Gets or sets the manager for user. </summary>
        ///
        /// <value> The user manager. </value>

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login

        /// <summary>   Login. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="returnUrl">    URL of the return. </param>
        ///
        /// <returns>   A response stream to send to the Login View. </returns>

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            CreateAdminIfNeeded();
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login

        /// <summary>   Login. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="model">        The model. </param>
        /// <param name="returnUrl">    URL of the return. </param>
        ///
        /// <returns>   A response stream to send to the Login View. </returns>

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return View(model);
            }
        }

        //
        // GET: /Account/VerifyCode

        /// <summary>   Verify code. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="provider">     The provider. </param>
        /// <param name="returnUrl">    URL of the return. </param>
        /// <param name="rememberMe">   True to remember me. </param>
        ///
        /// <returns>   An asynchronous result that yields an ActionResult. </returns>

        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode

        /// <summary>   Verify code. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="model">    The model. </param>
        ///
        /// <returns>   An asynchronous result that yields an ActionResult. </returns>

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register

        /// <summary>   Registers this object. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <returns>   A response stream to send to the Register View. </returns>

        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register

        /// <summary>   Registers this object. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="model">    The model. </param>
        ///
        /// <returns>   A response stream to send to the Register View. </returns>

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                    // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                    // Send an email with this link
                    // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

                    return RedirectToAction("Index", "Home");
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ConfirmEmail

        /// <summary>   Confirm email. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="userId">   Identifier for the user. </param>
        /// <param name="code">     The code. </param>
        ///
        /// <returns>   An asynchronous result that yields an ActionResult. </returns>

        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        //
        // GET: /Account/ForgotPassword

        /// <summary>   Forgot password. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <returns>   A response stream to send to the ForgotPassword View. </returns>

        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
                // await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation

        /// <summary>   Forgot password confirmation. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <returns>   A response stream to send to the ForgotPasswordConfirmation View. </returns>

        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword

        /// <summary>
        /// (An Action that handles HTTP POST requests) resets the password described by model.
        /// </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="model">    The model. </param>
        ///
        /// <returns>   An asynchronous result that yields an ActionResult. </returns>

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation

        /// <summary>   Resets the password confirmation. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <returns>   A response stream to send to the ResetPasswordConfirmation View. </returns>

        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin

        /// <summary>   (An Action that handles HTTP POST requests) external login. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="provider">     The provider. </param>
        /// <param name="returnUrl">    URL of the return. </param>
        ///
        /// <returns>   A response stream to send to the ExternalLogin View. </returns>

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode

        /// <summary>   Sends a code. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="returnUrl">    URL of the return. </param>
        /// <param name="rememberMe">   True to remember me. </param>
        ///
        /// <returns>   An asynchronous result that yields an ActionResult. </returns>

        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode

        /// <summary>   Sends a code. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="model">    The model. </param>
        ///
        /// <returns>   An asynchronous result that yields an ActionResult. </returns>

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generate the token and send it
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback

        /// <summary>   Callback, called when the external login. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="returnUrl">    URL of the return. </param>
        ///
        /// <returns>   An asynchronous result that yields an ActionResult. </returns>

        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation

        /// <summary>
        /// (An Action that handles HTTP POST requests) external login confirmation.
        /// </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="model">        The model. </param>
        /// <param name="returnUrl">    URL of the return. </param>
        ///
        /// <returns>   An asynchronous result that yields an ActionResult. </returns>

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff

        /// <summary>   (An Action that handles HTTP POST requests) log off. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <returns>   A response stream to send to the LogOff View. </returns>

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure

        /// <summary>   External login failure. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <returns>   A response stream to send to the ExternalLoginFailure View. </returns>

        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Helpers

        // Used for XSRF protection when adding external logins
        /// <summary>   The xsrf key. </summary>
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        /// <summary>   Adds the errors. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="result">   The result. </param>

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        /// <summary>   Redirect to local. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>
        ///
        /// <param name="returnUrl">    URL of the return. </param>
        ///
        /// <returns>   A response stream to send to the RedirectToLocal View. </returns>

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion

        #region public ApplicationRoleManager RoleManager

        /// <summary>   Manager for role. </summary>
        private ApplicationRoleManager _roleManager;
        public ApplicationRoleManager RoleManager
        {
            get
            {
                return _roleManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
            private set
            {
                _roleManager = value;
            }
        }
        #endregion
        //Add CreateAdminIfNeeded
        #region private void CreateAdminIfNeeded()

        /// <summary>   Creates admin if needed. </summary>
        ///
        /// <remarks>   Lukas, 30.01.2019. </remarks>

        private void CreateAdminIfNeeded()
        {
            //get Admin Account
            string AdminUserName = ConfigurationManager.AppSettings["AdminUserName"];
            string AdminPassword = ConfigurationManager.AppSettings["AdminPassword"];
            //string AdminUserName = "Admin@Admin.com";
            //string AdminPassword = "Password#1";
            //see If Admin exists
            var objAdminUser = UserManager.FindByEmail(AdminUserName);
            if (objAdminUser == null)
            {
                //ssee if admin role exists
                if (!RoleManager.RoleExists("Administrator"))
                {
                    //create the admin role(if needed)
                    IdentityRole objAdminRole = new IdentityRole("Administrator");
                    RoleManager.Create(objAdminRole);
                }
                //create Admin user
                var objNewAdminUser = new ApplicationUser { UserName = AdminUserName, Email = AdminUserName };
                var AdminUserCreateResult = UserManager.Create(objNewAdminUser, AdminPassword);
                //put user in Admin role
                UserManager.AddToRole(objNewAdminUser.Id, "Administrator");
            }
        }
        #endregion
    }
}