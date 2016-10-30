<?php

/**
 * @file
 * Hooks and functions relevant to developers.
 */

/**
 * Hook_ldap_user_attrs_alter().
 *
 * Alter list of available drupal user targets (fields, properties, etc.)
 *   for ldap_user provisioning mapping form (admin/config/people/ldap/user)
 *
 * return array with elements of the form:
 * [<field_type>.<field_name>] => array(
 *   'name' => string for user friendly name for the UI,
 *   'source' => ldap attribute (even if target of sync.  this should be refactored at some point to avoid confusion)
 *   'configurable' =>
 *   'configurable_to_drupal'  0 | 1, is this configurable?
 *   'configurable_to_ldap' =>  0 | 1, is this configurable?
 *   'user_tokens' => <user_tokens>
 *   'convert' => 1 | 0 convert from binary to string for storage and comparison purposes
 *   'direction' => LdapUserConf::$provisioningDirectionToDrupalUser or LdapUserConf::$provisioningDirectionToLDAPEntry leave empty if configurable
 *   'config_module' => module providing syncing configuration.
 *   'prov_module' => module providing actual syncing of attributes.
 *   'prov_events' => array( see LdapUserConf )
 *
 * where
 * 'field_type' is one of the following:
 *   'property' (user property such as mail, picture, timezone that is not a field)
 *   'field' (any field attached to the user such as field_user_lname)
 *   'profile2' (profile2 fields)
 *   'data' ($user->data array.  field_name will be used as key such as $user->data[<field_name>] = mapped value
 * 'field_name' machine name of property, field, profile2 field, or data associative array key
 */
function hook_ldap_user_attrs_list_alter(&$available_user_attrs, &$params) {

  /** search for _ldap_user_attrs_list_alter for good examples
  * the general trick to implementing this hook is:
  *   make sure to specify config and sync module
  *   if its configurable by ldap_user module, don't specify convert, user_tokens, direction.  these will be set by UI and stored values
  *   be sure to merge with existing values as ldap_user configured values will already exist in $available_user_attrs
  */

}

/**
 * Allow modules to alter the user object in the context of an ldap entry
 * during synchronization.
 *
 * @param array $edit
 *   The edit array (see hook_user_insert). Make changes to this object as
 *   required.
 * @param array $ldap_user,
 *   for structure @see LdapServer::userUserNameToExistingLdapEntry()
 *   Array, the ldap user object relating to the drupal user.
 * @param object $ldap_server
 *   The LdapServer object from which the ldap entry was fetched.
 * @param int $prov_event
 */
function hook_ldap_user_edit_user_alter(&$edit, &$ldap_user, $ldap_server, $prov_event) {
  $edit['myfield'] = $ldap_server->getAttributeValue($ldap_user, 'myfield');
}
