
General LDAP Project Notes

LDAP Servers is base module or api module.  General LDAP functions belong in
LDAP Servers.

--------------------------------------------------------
Case Sensitivity and Character Escaping in LDAP Modules
--------------------------------------------------------

The class MassageFunctions should be used for dealing with case sensitivity
and character escaping consistently.

The general rule is codified in MassageFunctions which is:
- escape filter values and attribute values when querying ldap
- use unescaped, lower case attribute names when storing attribute names in arrays (as keys or values), databases, or object properties.
- use unescaped, mixed case attribute values when storing attribute values in arrays (as keys or values), databases, or object properties.

So a filter might be built as follows:
  $massage = new MassageFunctions;
  $username = $massage->massage_text($username, 'attr_value', $massage::$query_ldap)
  $objectclass = $massage->massage_text($objectclass, 'attr_value', $massage::$query_ldap)
  $filter = "(&(cn=$username)(objectClass=$objectclass))";


The following functions are also available:
escape_dn_value()
unescape_dn_value()
unescape_filter_value()
unescape_filter_value()


--------------------------------------------------------
common variables used in ldap_* and their structures
--------------------------------------------------------

!Structure of $ldap_user and $ldap_entry are different!

-----------
$ldap_user
-----------
@see LdapServer::userUserNameToExistingLdapEntry() return

-----------
$ldap_entry and $ldap_*_entry.
-----------
@see LdapServer::ldap_search() return array


--------------
$user_attr_key
key of form <attr_type>.<attr_name>[:<instance>] such as field.lname, property.mail, field.aliases:2
--------------
