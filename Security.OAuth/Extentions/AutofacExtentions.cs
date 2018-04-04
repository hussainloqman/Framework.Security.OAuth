namespace Framework.Security.OAuth
{
    using ApplicationProviders;
    using Autofac;

    using Microsoft.Owin.Security.Infrastructure;
    using Microsoft.Owin.Security.OAuth;
    using Owin;
    using UserValidators;

    public static class AutofacExtentions
    {
        #region Methods

        public static void RegisterOAuth(this ContainerBuilder builder, bool refreshTokenEnabled)
        {
            builder.RegisterType<OAuthServerProvider>().As<OAuthAuthorizationServerProvider>().SingleInstance();
            builder.RegisterType<OAuthRefreshTokenProvider>().As<IAuthenticationTokenProvider>().SingleInstance();
            builder.RegisterType<UserValidatorFactory>().InstancePerRequest();
            if(!refreshTokenEnabled)
            {
                builder.RegisterType<NoApplicationProvider>().As<IApplicationProvider>().SingleInstance();
            }
        }

        public static void RegisterOAuthApplicationProvider<TApplicationProvider>(this ContainerBuilder builder)
            where TApplicationProvider : IApplicationProvider
        {
            builder.RegisterType<TApplicationProvider>().As<IApplicationProvider>().InstancePerRequest();
        }

        public static void RegisterOAuthUserValidator<TUserValidator>(this ContainerBuilder builder, string grantType)
            where TUserValidator : IUserValidator
        {
            builder.RegisterType(typeof(TUserValidator)).Named<IUserValidator>(grantType).InstancePerRequest();
        }

        #endregion Methods
    }
}