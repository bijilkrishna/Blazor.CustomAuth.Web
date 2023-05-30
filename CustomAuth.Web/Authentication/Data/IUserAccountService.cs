namespace CustomAuth.Web.Authentication.Data
{
    public interface IUserAccountService
    {
        Task<UserAccount?> GetUserByUserNameAndPassword(string userName, string password);
    }
}