using System.DirectoryServices.AccountManagement;

namespace windows_exploration
{
    public class DomainDNSRecord
    {
        public required string Name { get; set; }
        public required string RecordType { get; set; }
        public required string Data { get; set; }
    }

    public class UserAccountControlChecker
    {
        private readonly UserPrincipal _user;

        public UserAccountControlChecker(UserPrincipal user)
        {
            _user = user ?? throw new ArgumentNullException(nameof(user));
        }

        public bool IsScript()
        {
            return HasFlag(UserAccountControl.Script);
        }

        public bool IsAccountDisable()
        {
            return HasFlag(UserAccountControl.AccountDisable);
        }

        public bool IsHomeDirRequired()
        {
            return HasFlag(UserAccountControl.HomeDirRequired);
        }

        public bool IsLockout()
        {
            return HasFlag(UserAccountControl.Lockout);
        }

        public bool IsPasswordNotRequired()
        {
            return HasFlag(UserAccountControl.PasswordNotRequired);
        }

        public bool IsPasswordCannotChange()
        {
            return HasFlag(UserAccountControl.PasswordCannotChange);
        }

        public bool IsEncryptedTextPasswordAllowed()
        {
            return HasFlag(UserAccountControl.EncryptedTextPasswordAllowed);
        }

        public bool IsTempDuplicateAccount()
        {
            return HasFlag(UserAccountControl.TempDuplicateAccount);
        }

        public bool IsNormalAccount()
        {
            return HasFlag(UserAccountControl.NormalAccount);
        }

        public bool IsInterdomainTrustAccount()
        {
            return HasFlag(UserAccountControl.InterdomainTrustAccount);
        }

        public bool IsWorkstationTrustAccount()
        {
            return HasFlag(UserAccountControl.WorkstationTrustAccount);
        }

        public bool IsServerTrustAccount()
        {
            return HasFlag(UserAccountControl.ServerTrustAccount);
        }

        public bool IsDontExpirePassword()
        {
            return HasFlag(UserAccountControl.DontExpirePassword);
        }

        public bool IsMnsLogonAccount()
        {
            return HasFlag(UserAccountControl.MnsLogonAccount);
        }

        public bool IsSmartcardRequired()
        {
            return HasFlag(UserAccountControl.SmartcardRequired);
        }

        public bool IsTrustedForDelegation()
        {
            return HasFlag(UserAccountControl.TrustedForDelegation);
        }

        public bool IsNotDelegated()
        {
            return HasFlag(UserAccountControl.NotDelegated);
        }

        public bool IsUseDesKeyOnly()
        {
            return HasFlag(UserAccountControl.UseDesKeyOnly);
        }

        public bool IsDontRequirePreauth()
        {
            return HasFlag(UserAccountControl.DontRequirePreauth);
        }

        public bool IsPasswordExpired()
        {
            return HasFlag(UserAccountControl.PasswordExpired);
        }

        public bool IsTrustedToAuthForDelegation()
        {
            return HasFlag(UserAccountControl.TrustedToAuthForDelegation);
        }

        public bool IsPartialSecretsAccount()
        {
            return HasFlag(UserAccountControl.PartialSecretsAccount);
        }

        private bool HasFlag(UserAccountControl flag)
        {
            int userAccountControl = _user.UserAccountControl.HasValue ? (int)_user.UserAccountControl : 0;
            return (userAccountControl & (int)flag) == (int)flag;
            UserAccountControl
        }
    }
}