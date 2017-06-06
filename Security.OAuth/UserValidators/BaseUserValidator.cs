namespace Framework.Security.OAuth.UserValidators
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    public abstract class BaseUserValidator<TParam> : IUserValidator
        where TParam : new()
    {
        #region Methods

        bool IUserValidator.Validate(Dictionary<string, string> param, IApplication application, out IUser user)
        {
            var tparam = new TParam();
            foreach(var prop in typeof(TParam).GetProperties().Where(p=>p.CanWrite))
            {
                var key = prop.Name.ToLower();
                if (param.ContainsKey(key))
                    prop.SetValue(tparam, param[key]);
            }
            //-----------------------------------------------------------------------------
            return this.Validate(tparam, application, out user);
        }

        protected abstract bool Validate(TParam param, IApplication application, out IUser user);

        #endregion Methods
    }
}