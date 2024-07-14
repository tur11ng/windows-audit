using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;

namespace windows_exploration
{
    public class UserFilterBuilder
    {
        private readonly List<Func<UserPrincipal, bool>> _criteria;

        public UserFilterBuilder()
        {
            _criteria = new List<Func<UserPrincipal, bool>>();
        }

        public UserFilterBuilder IsActive(bool isActive)
        {
            _criteria.Add(user => user.IsActive == isActive);
            return this;
        }

        public UserFilterBuilder InDepartment(string department)
        {
            _criteria.Add(user => user.Department == department);
            return this;
        }

        public UserFilterBuilder OlderThan(int age)
        {
            _criteria.Add(user => user.Age > age);
            return this;
        }

        public IEnumerable<UserPrincipal> Apply(IEnumerable<UserPrincipal> users)
        {
            var combinedCriteria = _criteria.Aggregate((current, next) => user => current(user) && next(user));
            return users.Where(combinedCriteria);
        }
    }

// Extension method to combine predicates
    public static class PredicateExtensions
    {
        public static Func<T, bool> AndAlso<T>(this Func<T, bool> predicate1, Func<T, bool> predicate2)
        {
            return arg => predicate1(arg) && predicate2(arg);
        }
    }

    public static List<UserPrincipal> GetForestInactiveUsers(int inactiveDays)
    {
        DateTime inactiveDate = DateTime.Now.AddDays(-inactiveDays);
        Forest forest = Forest.GetCurrentForest();
        List<UserPrincipal> inactiveUsers = new List<UserPrincipal>();

        foreach (Domain domain in forest.Domains)
        {
            using PrincipalContext context = new PrincipalContext(ContextType.Domain, domain.Name);
            using UserPrincipal userPrincipal = new UserPrincipal(context);
            userPrincipal.Enabled = true;
            using PrincipalSearcher searcher = new PrincipalSearcher(userPrincipal);

            foreach (Principal result in searcher.FindAll())
            {
                var user = result as UserPrincipal;
                user.
                if (user != null && user.LastLogon.HasValue && user.LastLogon.Value < inactiveDate)
                {
                    inactiveUsers.Add(user);
                }
            }
        }

        return inactiveUsers;
    }

    private static List<string> GetUserGroups(UserPrincipal user)
    {
        List<string> groups = new List<string>();
        foreach (GroupPrincipal group in user.GetAuthorizationGroups())
        {
            groups.Add(group.Name);
        }

        return groups;
    }
}