<?php

namespace Drupal\ldap_servers\LdapTypes;

/**
 *
 */
class ActiveDirectoryType extends AbstractType {

  // Generic properties.
  public $name = 'Active Directory LDAP';
  public $typeId = 'ActiveDirectory';
  public $description = 'Microsoft Active Directory';

  // ldap_servers configuration.
  public $port = 389;
  public $tls = 1;
  public $encrypted = 0;
  public $user_attr = 'sAMAccountName';
  public $mail_attr = 'mail';

  /**
   * The following pairs all work in Active Directory,
   * but there is no assurance that any of them will survive
   * domain merges and migrations.  Its best to pick a true user id
   * such as a numeric one given to the user by the organization.
   *
   * UidNumber  - not binary
   * objectSid  - binary
   * objectGuid - binary.
   */

  public $unique_persistent_attr = 'uidNumber';
  public $unique_persistent_attr_binary = FALSE;



  public $groupObjectClassDefault = 'group';

  // ldap_authorization configuration.
  public $groupDerivationModelDefault = self::DERIVE_GROUP_FROM_ATTRIBUTE;
  public $deriveFromAttr = TRUE;
  public $groupUserMembershipsAttr = 'memberOf';

}
