using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIsSecures.APIsToken
{
    public class User
    {
        public string Name { get; set; }
        public string Pwd { get; set; }
        public string Role { get; set; }
    }
    public class AuthorizationManager : IAuthorizationManager
    {
        int tokenTimeout;
        private readonly IList<User> users = new List<User>();
        public AuthorizationManager(IConfiguration configuration)
        {
            for (int i = 0; i <= 2; i++)
            {
                var vTemp = configuration.GetSection("AppSettings").GetSection("APIKey" + i).Value;
                string[] vSplit = vTemp.Split(';');
                users.Add(new User() { Name = vSplit[0], Pwd = vSplit[1], Role = vSplit[2] });
            }
            tokenTimeout = Convert.ToInt16(configuration.GetSection("AppSettings").GetSection("TokenTimeout").Value);
        }

        private readonly IDictionary<string, Tuple<string, string, DateTime>> tokens =
            new Dictionary<string, Tuple<string, string, DateTime>>();

        public IDictionary<string, Tuple<string, string, DateTime>> Tokens => tokens;

        public string Authenticate(string username, string password)
        {
            if (!users.Any(u => u.Name == username && u.Pwd == password))
            {
                return null;
            }

            var token = Guid.NewGuid().ToString().ToUpper();
            var vTemp = users.ToList().Find(x => x.Name == username && x.Pwd == password);
            Tuple<string, string, DateTime> vTuple = new Tuple<string, string, DateTime>(vTemp.Name, vTemp.Role, DateTime.Now);
            //for (int i = 0; i < tokens.Count; i++)
            //{
            //    var vItem = tokens.ElementAtOrDefault(i);
            //    if (vItem.Value.Equals(vTuple))
            //    {
            //        tokens.Remove(vItem.Key);
            //        break;
            //    }
            //}
            var vKey = tokens.ToList().Find(x => x.Value.Item1 == vTuple.Item1 && x.Value.Item2 == vTuple.Item2).Key;
            if (vKey != null)
                tokens.Remove(vKey);
            tokens.Add(token, vTuple);

            return token;
        }
        //===============================================================================
    }
}
