using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using SansSoussi.Models;
using Microsoft.Web.WebPages.OAuth;
using DotNetOpenAuth.GoogleOAuth2;
using System.Collections.Generic;

namespace SansSoussi.App_Start
{
    public class AuthConfig
    {
        public static void RegisterAuth()
        {
            var client = new GoogleOAuth2Client("242561533642-qelkgu4usmftj9g84k94ci17j37smg9e.apps.googleusercontent.com", "PdZpOl2UhKYdmtX-xLtqD4hl");
            var extraData = new Dictionary<string, object>();
            OAuthWebSecurity.RegisterClient(client, "Google", extraData);
        }
    }
}