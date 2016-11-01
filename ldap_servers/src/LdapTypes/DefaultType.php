<?php

namespace Drupal\ldap_servers\LdapTypes;

/**
 *
 */
class DefaultType extends AbstractType {

  public $name = 'Default LDAP';
  public $typeId = 'Default';
  public $description = 'Other LDAP Type';
  public $port = 389;
  public $tls = 1;
  public $encrypted = 0;
  public $user_attr = 'cn';
  public $mail_attr = 'mail';
  public $supportsNestGroups = FALSE;

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
