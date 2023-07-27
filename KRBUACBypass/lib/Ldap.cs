using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.DirectoryServices.Protocols;

namespace KRBUACBypass
{
    public class Ldap
    {
        public static SearchResultEntryCollection GetSearchResultEntries(LdapConnection connection, string distinguishedName, string ldapFilter, System.DirectoryServices.Protocols.SearchScope searchScope, string[] attributeList)
        {
            SearchRequest searchRequest = new SearchRequest(distinguishedName, ldapFilter, searchScope, attributeList);
            // The SecurityDescriptorFlagControl class is used to pass flags to the server to control various security descriptor behaviors.
            searchRequest.Controls.Add(new SecurityDescriptorFlagControl(System.DirectoryServices.Protocols.SecurityMasks.Dacl));
            SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
            return searchResponse.Entries;
        }
    }


}
