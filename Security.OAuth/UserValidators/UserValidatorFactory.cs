namespace Framework.Security.OAuth.UserValidators
{
    using Autofac;

    internal class UserValidatorFactory
    {
        #region Fields

        private ILifetimeScope _scope;

        #endregion Fields

        #region Constructors

        public UserValidatorFactory(ILifetimeScope scope)
        {
            _scope = scope;
        }

        #endregion Constructors

        #region Methods

        public IUserValidator GetValidator(string grantType)
        {
            object validator = null;
            if (_scope.TryResolveNamed(grantType, typeof(IUserValidator), out validator))
                return (IUserValidator)validator;
            return null;
        }

        #endregion Methods
    }
}