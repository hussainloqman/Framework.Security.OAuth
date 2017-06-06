namespace Framework.Security.OAuth.UserValidators
{
    using System;

    public class PasswordGrantType
    {
        #region Properties

        public string Password
        {
            set; get;
        }

        public string Username
        {
            set; get;
        }

        #endregion Properties
    }
}