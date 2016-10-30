

------------------
Configuration Work:
------------------
X  Check in ldap 7.x-2.x-dev into drupal 8 branch for diffing
X  Convert .info files to .info.yml files
X  add config directories and default settings files
X  deal with standard variables that map directly to new config model

deal with all system_settings_form() instances and resulting variables
deal with large setting arrays stored in single variables: ldap_authentication_conf, ldap_user_conf
deal with configurations that are backended by tables (ldapServers, ldap_query, etc.)
deal with variable_get('ldap_test_server__' . $sid, NULL);
deal with all instances of variable_del()
deal with all instances of variable_set()
need to deal with changes to pictures and related variables (user_picture_*):  //@todo needs to change to reflect new approach to user picture: http://drupal.org/node/1851200
remove all ctools requirements and load process for ldap_servers, ldap_query, etc.

--------------------
function changes
--------------------

Examine all module hooks and see which have changed
Examine all other core api functions being used and see what has changed. grep for core module functions such as ' user_*'


--------------------
cleanup
--------------------

Phase out any less than useful ldap functions such as ldap_servers_load_module
get rid of og 1.5 support

--------------------
misc notes
--------------------
function user_update_8004() {
  update_variables_to_config('user.settings', array(
    'anonymous' => 'anonymous',
    'user_admin_role' => 'admin_role',
    'user_register' => 'register',
    'user_signatures' => 'signatures',
    'user_cancel_method' => 'cancel_method',
    'user_mail_status_activated_notify' => 'notify.status_activated',
    'user_mail_status_blocked_notify' => 'notify.status_blocked',
    'user_mail_status_cancelled_notify' => 'notify.status_cancelled',
    'user_email_verification' => 'verify_mail',
    'user_password_reset_timeout' => 'password_reset_timeout',
  ));


    update_variables_to_config('system.site', array(
      'site_name' => 'name',
      'site_mail' => 'mail',
      'site_slogan' => 'slogan',
      'site_frontpage' => 'page.front',
      'site_403' => 'page.403',
      'site_404' => 'page.404',
      'drupal_weight_select_max' => 'weight_select_max',
    ));


====================================
Post Migration Cleanup
Tokens: Consisent user and ldap entry tokens
Tokens: Leverage token module
