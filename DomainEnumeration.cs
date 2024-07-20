using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;

namespace windows_exploration
{
    public class DomainEnumeration
    {
        private static readonly string[] PrivilegedGroups = new string[] {
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators"
        };

        public static IEnumerable<UserPrincipal> GetDomainUsers(string domainName)
        {
            using PrincipalContext context = new(ContextType.Domain, domainName);
            using UserPrincipal userPrincipal = new(context) { Enabled = true };
            using PrincipalSearcher searcher = new(userPrincipal);

            foreach (Principal result in searcher.FindAll())
            {
                UserPrincipal? user = result as UserPrincipal;

                if (user != null)
                {
                    yield return user;
                }
            }
        }

        public static IEnumerable<GroupPrincipal> GetDomainGroups(string domainName)
        {
            using PrincipalContext context = new(ContextType.Domain, domainName);
            using GroupPrincipal groupPrincipal = new(context);
            using PrincipalSearcher searcher = new(groupPrincipal);

            foreach (Principal result in searcher.FindAll())
            {
                GroupPrincipal? group = result as GroupPrincipal;

                if (group != null)
                {
                    yield return group;
                }
            }
        }

        public static IEnumerable<UserPrincipal> GetGroupMembers(GroupPrincipal group, bool recursive)
        {
            foreach (var principal in group.GetMembers(recursive))
            {
                if (principal is UserPrincipal user)
                {
                    yield return user;
                }
                else if (principal is GroupPrincipal nestedGroup && recursive)
                {
                    foreach (var nestedUser in GetGroupMembers(nestedGroup, recursive))
                    {
                        yield return nestedUser;
                    }
                }
            }
        }

        public static Dictionary<GroupPrincipal, IEnumerable<UserPrincipal>> GetDomainPrivilegedGroupsMembers(string domainName, bool recursive)
        {
            var context = new PrincipalContext(ContextType.Domain, domainName);
            var groups = new Dictionary<GroupPrincipal, IEnumerable<UserPrincipal>>();

            foreach (var groupName in PrivilegedGroups)
            {
                var group = GroupPrincipal.FindByIdentity(context, groupName);
                if (group != null)
                {
                    var members = GetGroupMembers(group, recursive);
                    groups.Add(group, GetGroupMembers(group, recursive));
                }
            }

            return groups;
        }

        public static IEnumerable<DirectoryEntry> GetDomainObjectsInterestingACL(string domainName) {
            string domainPath = "LDAP://YourDomain"; // Replace with your actual domain path
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(domainPath))
                using (DirectorySearcher searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = "(objectClass=*)"; // Search for all objects
                    searcher.PageSize = 1000;

                    foreach (SearchResult result in searcher.FindAll())
                    {
                        DirectoryEntry de = result.GetDirectoryEntry();
                        AnalyzeAcl(de);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        } 
    }
}