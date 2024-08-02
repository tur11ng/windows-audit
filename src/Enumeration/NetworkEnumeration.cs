using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace windows_exploration
{
    class Credential
    {
        public string Username { get; set; }
        public string Password { get; set; }

        public Credential(string username, string password)
        {
            Username = username;
            Password = password;
        }
    }

    class CredentialsChecker
    {

        private static Credential? CheckForHttpCredentials(string payload)
        {
            if (payload.Contains("Authorization: Basic"))
            {
                var startIndex = payload.IndexOf("Authorization: Basic") + "Authorization: Basic".Length;
                var endIndex = payload.IndexOf("\r\n", startIndex);
                var base64Credentials = payload.Substring(startIndex, endIndex - startIndex).Trim();
                var decodedCredentials = Encoding.ASCII.GetString(Convert.FromBase64String(base64Credentials));
                var parts = decodedCredentials.Split(':');
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForFtpCredentials(string payload)
        {
            if (payload.StartsWith("USER ") || payload.StartsWith("PASS "))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForTelnetCredentials(string payload)
        {
            if (payload.Contains("login: ") || payload.Contains("Password: "))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForPop3Credentials(string payload)
        {
            if (payload.StartsWith("USER ") || payload.StartsWith("PASS "))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForImapCredentials(string payload)
        {
            if (payload.Contains(" LOGIN "))
            {
                var parts = payload.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                return new Credential(parts[1], parts[2]);
            }
            return null;
        }

        private static Credential? CheckForSmtpCredentials(string payload)
        {
            if (payload.Contains("AUTH LOGIN"))
            {
                var startIndex = payload.IndexOf("AUTH LOGIN") + "AUTH LOGIN".Length;
                var endIndex = payload.IndexOf("\r\n", startIndex);
                var base64Credentials = payload.Substring(startIndex, endIndex - startIndex).Trim();
                var decodedCredentials = Encoding.ASCII.GetString(Convert.FromBase64String(base64Credentials));
                var parts = decodedCredentials.Split(':');
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForLdapCredentials(string payload)
        {
            if (payload.Contains("bindRequest"))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForSnmpCredentials(string payload)
        {
            if (payload.Contains("community"))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForRloginCredentials(string payload)
        {
            if (payload.Contains("\0"))
            {
                var parts = payload.Split(new[] { '\0' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForMysqlCredentials(string payload)
        {
            if (payload.Contains("mysql_native_password"))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForPostgresqlCredentials(string payload)
        {
            if (payload.Contains("user") && payload.Contains("password"))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForIrcCredentials(string payload)
        {
            if (payload.Contains("PASS "))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForNntpCredentials(string payload)
        {
            if (payload.StartsWith("AUTHINFO USER ") || payload.StartsWith("AUTHINFO PASS "))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForXmppCredentials(string payload)
        {
            if (payload.Contains("<auth "))
            {
                var parts = payload.Split(new[] { ' ' }, 2);
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }

        private static Credential? CheckForRtspCredentials(string payload)
        {
            if (payload.Contains("Authorization: Basic"))
            {
                var startIndex = payload.IndexOf("Authorization: Basic") + "Authorization: Basic".Length;
                var endIndex = payload.IndexOf("\r\n", startIndex);
                var base64Credentials = payload.Substring(startIndex, endIndex - startIndex).Trim();
                var decodedCredentials = Encoding.ASCII.GetString(Convert.FromBase64String(base64Credentials));
                var parts = decodedCredentials.Split(':');
                return new Credential(parts[0], parts[1]);
            }
            return null;
        }
    }
}
