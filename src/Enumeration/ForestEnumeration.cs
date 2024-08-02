using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;

namespace windows_exploration
{
    public class ForestEnumeration
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
        
        public static IEnumerable<GroupPrincipal> GetForestGroups() 
        {
            var forest = Forest.GetCurrentForest();
            foreach (Domain domain in forest.Domains)
            {
                foreach (var group in DomainEnumeration.GetDomainGroups(domain.Name))
                {
                    yield return group;
                }
            }
        }

        public static Dictionary<Domain, IEnumerable<UserPrincipal>> GetForestUsers()
        {
            var forest = Forest.GetCurrentForest();
            var dictionary = new Dictionary<Domain, IEnumerable<UserPrincipal>>();

            foreach (Domain domain in forest.Domains)
            {
                dictionary.Add(domain, DomainEnumeration.GetDomainUsers(domain.Name));
            }

            return dictionary;
        }

        public static Dictionary<Domain, Dictionary<GroupPrincipal, IEnumerable<UserPrincipal>>> GetForestPrivilegedGroupsMembers(bool recursive)
        {
            var forest = Forest.GetCurrentForest();
            var dictionary = new Dictionary<Domain, Dictionary<GroupPrincipal, IEnumerable<UserPrincipal>>>();

            foreach (Domain domain in forest.Domains)
            {
                dictionary.Add(domain, DomainEnumeration.GetDomainPrivilegedGroupsMembers(domain.Name, recursive));
            }

            return dictionary;
        }

        public static IEnumerable<GlobalCatalog> GetForestGlobalCatalogs() {
            var forest = Forest.GetCurrentForest();
            foreach (GlobalCatalog globalCatalog in forest.GlobalCatalogs)
            {
                yield return globalCatalog;
            }
        }
    }
}