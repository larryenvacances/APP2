using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using System.Web.Security;
using SansSoussi.Models;
using Microsoft.Web.WebPages.OAuth;
using DotNetOpenAuth.AspNet;
using DotNetOpenAuth.GoogleOAuth2;

namespace SansSoussi.Controllers
{
    public class AccountController : Controller
    {

        public IFormsAuthenticationService FormsService { get; set; }
        public IMembershipService MembershipService { get; set; }

        protected override void Initialize(RequestContext requestContext)
        {
            if (FormsService == null) { FormsService = new FormsAuthenticationService(); }
            if (MembershipService == null) { MembershipService = new AccountMembershipService(); }

            base.Initialize(requestContext);
        }

        // **************************************
        // URL: /Account/LogOn
        // **************************************

        public ActionResult LogOn(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View(OAuthWebSecurity.RegisteredClientData);
        }

        // **************************************
        // URL: /Account/ExternalLogin
        // **************************************
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public void ExternalLogin(string provider, string returnUrl)
        {
            OAuthWebSecurity.RequestAuthentication(provider, Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
        }

        [AllowAnonymous]
        public ActionResult ExternalLoginCallback(string returnUrl = "")
        {
            GoogleOAuth2Client.RewriteRequest();

            AuthenticationResult result = OAuthWebSecurity.VerifyAuthentication(Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
            if (!result.IsSuccessful)
            {
                return RedirectToAction("ExternalLoginFailure");
            }

            //if (OAuthWebSecurity.Login(result.Provider, result.ProviderUserId, createPersistentCookie: false))
            //{
            //    return RedirectToLocal(returnUrl);
            //}

            if (User.Identity.IsAuthenticated)
            {
                return RedirectToLocal(returnUrl);
            }
            else
            {
                if (MembershipService.ValidateUserFromExternalAuth(result))
                {
                    FormsService.SignIn(result.ExtraData["name"], false);
                    if (Url.IsLocalUrl(returnUrl))
                    {
                        return Redirect(returnUrl);
                    }
                    else
                    {
                        //Encode the username in base64
                        byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(result.ExtraData["name"]);
                        HttpCookie authCookie = new HttpCookie("username", System.Convert.ToBase64String(toEncodeAsBytes));
                        HttpContext.Response.Cookies.Add(authCookie);
                        return RedirectToAction("Index", "Home");
                    }
                }
                else
                {
                    // Attempt to register the user
                    MembershipCreateStatus createStatus = MembershipService.CreateUserFromExternalAuth(result);

                    if (createStatus == MembershipCreateStatus.Success)
                    {
                        FormsService.SignIn(result.ExtraData["name"], false /* createPersistentCookie */);
                        //Encode the username in base64
                        byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(result.ExtraData["name"]);
                        HttpCookie authCookie = new HttpCookie("username", System.Convert.ToBase64String(toEncodeAsBytes));
                        HttpContext.Response.Cookies.Add(authCookie);
                        return RedirectToAction("Index", "Home");
                    }
                    else
                    {
                        ModelState.AddModelError("", AccountValidation.ErrorCodeToString(createStatus));
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            ViewBag.PasswordLength = MembershipService.MinPasswordLength;
            return RedirectToLocal("");
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        // **************************************
        // URL: /Account/LogOff
        // **************************************

        public ActionResult LogOff()
        {
            FormsService.SignOut();

            return RedirectToAction("Index", "Home");
        }
    }
}
