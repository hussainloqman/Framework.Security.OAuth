# Framework.Security.OAuth
a simple wrappr for OAUth to enable simple OAuth Implementation over owin

**Use nuget**
```
Install-Package Security.OAuth
```

####Using

##### configuring the middleware 
In your resource server use the nuget package `Microsoft.Owin.Security.OAuth`

```
app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
```

In your security Authorization server use this nuget package 

```
app.MapOAuthServer(container, 20160,"/token");
```

##### configuring the Dependency Resolver 
```
builder.RegisterOAuth(true);
builder.RegisterOAuthApplicationProvider<ApplicationProvider>();
builder.RegisterOAuthUserValidator<PasswordUserValidator>("password");
builder.RegisterOAuthUserValidator<FacebookUserValidator>("facebook");
builder.RegisterOAuthUserValidator<GoogleUserValidator>("google");
```
use can pass `false` to the RegisterOAuth to disable the refresh token, but if you pass true to have to supply `RegisterOAuthApplicationProvider` with your own Implementation of the `IApplicationProvider` or `BaseApplicationProvider` 

a simple implementation will look like this 

```
public class ApplicationProvider : BaseApplicationProvider
{
     public override bool ValidateApplication(string id, string secret, out IApplication application)
     {
            application = null;
            return true;
     }
}
```

for each grant type you have to supply your own implementation of it 

a simple implementation of grant type `password` will be 

```
public class PasswordUserValidator : BaseUserValidator<PasswordGrantType>
{
    protected override bool Validate(PasswordGrantType param, IApplication application, out IUser user)
    {
         User dbUser = null;
         return true;
    }
}
```

