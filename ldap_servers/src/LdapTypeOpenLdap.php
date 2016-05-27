<?php
namespace Drupal\ldap_servers;
/**
 *
 */
class LdapTypeOpenLdap extends LdapTypeAbstract {

  // Generic properties.
  public $documentation = '';
  public $name = 'openLDAP LDAP';
  public $typeId = 'OpenLdap';
  public $description = 'openLDAP LDAP';

  // ldap_servers configuration.
  public $tls = 0;
  public $encrypted = 0;
  public $user_attr = 'cn';
  public $mail_attr = 'mail';
  public $unique_persistent_attr = 'entryUUID';
  public $unique_persistent_attr_binary = FALSE;
  public $groupObjectClassDefault = 'groupofnames';

  // ldap_authorization configuration.
  public $groupDerivationModelDefault = LDAP_SERVERS_DERIVE_GROUP_FROM_ENTRY;
  public $groupMembershipsAttr = 'member';
  public $groupMembershipsAttrMatchingUserAttr = 'dn';

}
