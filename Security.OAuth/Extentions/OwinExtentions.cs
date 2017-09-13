namespace Framework.Security.OAuth
{
    using System;

    using Autofac;
    using Autofac.Core.Lifetime;

    using Microsoft.Owin;
    using Microsoft.Owin.Security.Infrastructure;
    using Microsoft.Owin.Security.OAuth;

    using global::Owin;
    using ApplicationProviders;
    using UserValidators;

    public static class OAuthAuthorizationServerExtention
    {
        #region Methods

        public static IAppBuilder MapOAuthServer(this IAppBuilder app, ILifetimeScope dependencyResolver, string tokenPath = "/token", double accessTokenExpirationMinutes = 20, double? clientCredsTokensExpiration = null, bool allowInsecureHttp = false)
        {
            app.Map(tokenPath, subApp => subApp.Use((ctx, next) =>
             {
                 var scope = dependencyResolver.BeginLifetimeScope(MatchingScopeLifetimeTags.RequestLifetimeScopeTag);
                 ctx.Set("IApplicationProvider", scope.Resolve<IApplicationProvider>());
                 ctx.Set("UserValidatorFactory", scope.Resolve<UserValidatorFactory>());
                 if (clientCredsTokensExpiration.HasValue)
                     ctx.Set("ClientCreadsExpiration", clientCredsTokensExpiration.Value);
                 return next();
             }));
            OAuthAuthorizationServerOptions options = new OAuthAuthorizationServerOptions()
            {
                TokenEndpointPath = new PathString(tokenPath),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(accessTokenExpirationMinutes),
                Provider = dependencyResolver.Resolve<OAuthAuthorizationServerProvider>(),
                RefreshTokenProvider = dependencyResolver.Resolve<IAuthenticationTokenProvider>(),
                AllowInsecureHttp = allowInsecureHttp
            };
            app.UseOAuthAuthorizationServer(options);
            return app;
        }

        #endregion Methods
    }
}