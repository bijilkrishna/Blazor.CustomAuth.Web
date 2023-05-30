namespace CustomAuth.Web.Authentication.Data
{
    public class UserAccountService : IUserAccountService
    {
        private readonly List<UserAccount> _users;
        public UserAccountService()
        {
            _users = new List<UserAccount>()
            {
                new UserAccount{UserName="User", Password="User",Role="User"},
                new UserAccount{UserName="Admin" ,Password="Admin",Role ="Admin"}
            };
        }
        public Task<UserAccount?> GetUserByUserNameAndPassword(string userName, string password)
        {
            var userdetail= _users.Where(
                u => u.UserName == userName && u.Password == password
                )?.FirstOrDefault();
            return Task.FromResult(userdetail);
        }
    }
}
