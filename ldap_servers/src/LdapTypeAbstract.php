<?php

namespace Drupal\ldap_servers;

/**
 * @file
 * Abstract class to represent an ldap implementation type
 * such as active directory, open ldap, novell, etc.
 */
abstract class LdapTypeAbstract {

  public $name;
  public $typeId;
  public $description;

  // ldap_servers configuration.
  public $port = 389;
  public $tls = 0;
  public $encrypted = 0;
  public $user_attr = 'cn';
  public $mail_attr = 'mail';
  public $groupObjectClassDefault = NULL;
  public $groupDerivationModelDefault = NULL;

  // ldap_authorization configuration.
  public $deriveFromDn = FALSE;
  public $deriveFromAttr = FALSE;
  public $deriveFromEntry = FALSE;
  public $groupMembershipsAttr = NULL;
  // Can be removed in 2.0 branch.
  public $groupMembershipsAttrMatchingUserAttr = FALSE;

  /**
   * Constructor Method.
   */
  public function __construct($params = array()) {
    foreach ($params as $k => $v) {
      if (property_exists($this, $k)) {
        $this->{$k} = $v;
      }
    }
  }

}
