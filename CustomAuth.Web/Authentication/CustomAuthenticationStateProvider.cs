using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Security.Claims;

namespace CustomAuth.Web.Authentication
{
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly ProtectedSessionStorage protectedSessionStorage;
        private ClaimsPrincipal _annonymous = new ClaimsPrincipal(new ClaimsIdentity()); 

        public CustomAuthenticationStateProvider(ProtectedSessionStorage protectedSessionStorage)
        {
            this.protectedSessionStorage = protectedSessionStorage;
        }
        public async override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                var userSessionResult = await this.protectedSessionStorage.GetAsync<UserSession>("UserSession");
                var userSession = userSessionResult.Success ? userSessionResult.Value : null;
                if (userSession == null)
                {
                    //there is no valid users session found so return the annonymous claims principal
                    return await Task.FromResult(new AuthenticationState(_annonymous));
                }
                //valid session detils found , so create a new claimsPrincipal for it and sendback the 
                //autheniction state along with it .
                var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
                    new List<Claim>
                    {
                    new Claim(ClaimTypes.Name,userSession.UserName),
                    new Claim(ClaimTypes.Role,userSession.Role)
                    },"CustomAuth"));
                return await Task.FromResult(new AuthenticationState(claimsPrincipal));
            }
            catch
            {
                // there is something wrong happened with the session storage data , it might go tampered 
                // so set the authetication state to annonymous  
                return await Task.FromResult(new AuthenticationState(_annonymous)); 
            }
            
        }
        public async Task UpdateAuthenticationState(UserSession userSession)
        {
            ClaimsPrincipal claimsPrincipal;
            if(userSession != null)
            {
                //this is from the login action .Set the session and create the Claims priciple
                //for the NotifyAuthenticationStateChanged
                await this.protectedSessionStorage.SetAsync("UserSession", userSession);
                claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
                {
                   new Claim( ClaimTypes.Name,userSession.UserName),
                   new Claim(ClaimTypes.Role, userSession.Role)
                }));

            }
            else
            {
                //this should be from the log out action
                // clear of the session variable
                await this.protectedSessionStorage.DeleteAsync("UserSession");
                //set the claims principal to anonymous 
                claimsPrincipal = _annonymous;
            }
             NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }
    }
}
