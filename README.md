The current state of the LDAP module is still in-flux while the port to Drupal 8
is ongoing. The majority of the core functionality is available and usable but
caution should be taken for more complex scenarios such as provisioning to LDAP.

Please see INSTALL.md for specific information on setting up the Drupal LDAP
suite.

For more information review the following resources:

* [Project page](https://www.drupal.org/project/ldap)
* [Issue for Drupal 8 port](https://www.drupal.org/node/2259385)


## Module overview

| Module | Description |
| ------ | ----------- |
| ldap_authentication | This module provides a overall authentication functionality closely tied to ldap_user and ties in with several other modules, such as ldap_sso. |
| ldap_authorization | The module to grant roles to users based on directory criteria, relies on the externalauth module. |
| ldap_feeds (Unported) | Feeds integration to automatically sync users. |
| ldap_help | A debugging module to help you discover additional information through detailed logging.  |
| ldap_query | A module to allow you to execute custom queries, which can be display in Views or used in custom solutions. |
| ldap_servers | The base module for communicating with a directory. |
| ldap_sso | Provides Kerberos/NTLM single-sign-on. Note that this module is now a [separate project on drupal.org](https://www.drupal.org/project/ldap_sso). |
| ldap_user | A base module with low-level user functionality as well as mechanisms to sync user data. |

A common scenario for logging in users via LDAP, assigning groups to them and syncing user fields thus consists of
ldap_authentication, ldap_authorization, ldap_servers, ldap_user.

## Additional information

If you are not yet familiar with how LDAP operates or how directory services
work in general, the following links can be helpful resources. 

However, we recommend in any case that you contact your organization's directory
maintainer, since their help can often save you a significant amount of time in
debugging.

### General LDAP resources

* [Moodle LDAP module documentation](http://docs.moodle.org/20/en/LDAP_authentication) is well done and provides insight into LDAP in a PHP environment.
* [PHP LDAP](http://us.php.net/manual/en/book.ldap.php)
* [Apache Directory Studio](http://directory.apache.org/studio/) LDAP Browser and Directory Client.
* [Novell Edirectory](http://www.novell.com/documentation/edir873/index.html?page=/documentation/edir873/edir873/data/h0000007.html)
* [Apple Open Directory](http://images.apple.com/server/macosx/docs/Open_Directory_Admin_v10.5_3rd_Ed.pdf)
* [Microsoft Active Directory LDAP](http://msdn.microsoft.com/en-us/library/aa705886(VS.85).aspx)

### Example documentations from public universities

* [Northwestern University](http://www.it.northwestern.edu/bin/docs/CentralAuthenticationServicesThroughLDAP.pdf)
* [University of Washington](http://www.netid.washington.edu/documentation/ldapConfig.aspx)
* [University of Chicago](https://wiki.uchicago.edu/display/idm/LDAP)
* [UIOWA](https://www.icts.uiowa.edu/confluence/display/ICTSit/Drupal+LDAP+Integration+Against+Active+Directory)
