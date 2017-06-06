namespace Framework.Security.OAuth.UserValidators
{
    using System.Collections.Generic;

    public interface IUserValidator
    {
        #region Methods

        bool Validate(Dictionary<string,string> param, IApplication application, out IUser user);

        #endregion Methods
    }
}