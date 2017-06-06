namespace Framework.Security.OAuth.Owin
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.OAuth;
    using global::Security.OAuth.Properties;
    using ApplicationProviders;
    using UserValidators;

    public class OAuthServerProvider : OAuthAuthorizationServerProvider
    {
        #region Constructors

        public OAuthServerProvider()
        {

        }

        #endregion Constructors

        #region Methods

        // grant type = client_credentials
        public override Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            var application = context.OwinContext.Get<IApplication>("oh:application");
            if (application != null)
            {
                ClaimsIdentity identity = new ClaimsIdentity(context.Options.AuthenticationType);
                identity.AddClaim(new Claim(identity.NameClaimType, application.Name));
                identity.AddClaim(new Claim("Id", application.Id));
                identity.AddClaim(new Claim(identity.RoleClaimType, "Application"));
                foreach (var extra in application.AdditionalTokenParameters)
                    identity.AddClaim(new Claim(extra.Key, extra.Value));
                var props = new AuthenticationProperties(application.AdditionalResponseParameters);
                context.Validated(new AuthenticationTicket(identity, props));
            }
            return Task.FromResult<object>(null);
        }

        //grant type = others.
        public override Task GrantCustomExtension(OAuthGrantCustomExtensionContext context)
        {
            var usersValidatorFactory = context.OwinContext.Get<UserValidatorFactory>("UserValidatorFactory");
            var application = context.OwinContext.Get<IApplication>("oh:application");
            //------------------------------------------------------------------------------------------------
            IUser user;
            var validator = usersValidatorFactory.GetValidator(context.GrantType);
            if (validator == null)
                context.SetError(Resources.InvalidGrantType);
            var param = context.Request.ReadFormAsync().Result.ToDictionary(i => i.Key.Replace("_", ""), i => string.Join(",", i.Value));
            if (validator.Validate(param, application, out user))
            {
                ClaimsIdentity identity = new ClaimsIdentity(context.Options.AuthenticationType);
                AuthenticationProperties props = null;
                if (user != null)
                {
                    identity.AddClaim(new Claim(identity.NameClaimType, user.Username));
                    identity.AddClaim(new Claim("Id", user.Id));
                    foreach (var role in user.Roles)
                        identity.AddClaim(new Claim(identity.RoleClaimType, role));
                    foreach (var extra in user.AdditionalTokenParameters)
                        identity.AddClaim(new Claim(extra.Key, extra.Value));
                    props = new AuthenticationProperties(user.AdditionalResponseParameters);
                }
                context.Validated(new AuthenticationTicket(identity, props));
            }
            else
                context.SetError(Resources.InvalidUserCredentials);
            return Task.FromResult<Object>(null);
        }

        // grant type = refresh_token
        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var application = context.OwinContext.Get<IApplication>("oh:application");
            //-----------------------------------------------------------------------------------------------------------
            if (application != null)
            {
                context.OwinContext.Response.Headers.Remove("Access-Control-Allow-Origin");
                string[] origin = { "*" };
                if (application.AllowedOrigin != null)
                    origin = application.AllowedOrigin.Split(',');
                context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", origin);
            }
            //-----------------------------------------------------------------------------------------------------------
            if (context.Ticket != null)
                context.Validated(new AuthenticationTicket(context.Ticket.Identity, context.Ticket.Properties));
            else
                context.SetError(Resources.InvalidUserRefreshToken);
            return Task.FromResult<object>(null);
        }

        //grant type = password.
        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var application = context.OwinContext.Get<IApplication>("oh:application");
            var usersValidatorFactory = context.OwinContext.Get<UserValidatorFactory>("UserValidatorFactory");
            //-----------------------------------------------------------------------------------------------------------
            if (application != null)
            {
                context.OwinContext.Response.Headers.Remove("Access-Control-Allow-Origin");
                string[] origin = { "*" };
                if (application.AllowedOrigin != null)
                    origin = application.AllowedOrigin.Split(',');
                context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", origin);
            }
            //-----------------------------------------------------------------------------------------------------------
            IUser user;
            var userValidator = usersValidatorFactory.GetValidator("password");
            if (userValidator.Validate(
                new Dictionary<string, string> { { "username", context.UserName }, { "password", context.Password } },
                application,
                out user))
            {
                ClaimsIdentity identity = new ClaimsIdentity(context.Options.AuthenticationType);
                AuthenticationProperties props = null;
                if (user != null)
                {
                    identity.AddClaim(new Claim(identity.NameClaimType, user.Username));
                    identity.AddClaim(new Claim("Id", user.Id));
                    foreach (var role in user.Roles)
                        identity.AddClaim(new Claim(identity.RoleClaimType, role));
                    foreach (var extra in user.AdditionalTokenParameters)
                        identity.AddClaim(new Claim(extra.Key, extra.Value));
                    props = new AuthenticationProperties(user.AdditionalResponseParameters);
                }

                context.Validated(new AuthenticationTicket(identity, props));
            }
            else
                context.SetError(Resources.InvalidUserCredentials);

            return Task.FromResult<object>(null);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
                context.AdditionalResponseParameters.Add(property.Key, property.Value);

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            var applicationProvider = context.OwinContext.Get<IApplicationProvider>("IApplicationProvider");
            //-----------------------------------------------------------------------------------------------
            string clientId = string.Empty;
            string clientSecret = string.Empty;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
                context.TryGetFormCredentials(out clientId, out clientSecret);
            //-----------------------------------------------------------------------------------------------
            IApplication application;
            if (applicationProvider.ValidateApplication(clientId, clientSecret, out application))
            {
                context.Validated();
                context.OwinContext.Set("oh:application", application);
            }
            else
                context.SetError(Resources.InvalidApplication);

            return Task.FromResult<object>(null);
        }

        #endregion Methods
    }
}