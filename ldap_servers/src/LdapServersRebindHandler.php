<?php

namespace Drupal\ldap_servers;

/**
 * Class for enabling rebind functionality for following referrrals.
 */
class LdapServersRebindHandler {

  private $bind_dn = 'Anonymous';
  private $bind_passwd = '';

  /**
   *
   */
  public function __construct($bind_user_dn, $bind_user_passwd) {
    $this->bind_dn = $bind_user_dn;
    $this->bind_passwd = $bind_user_passwd;
  }

  /**
   *
   */
  public function rebind_callback($ldap, $referral) {
    // Ldap options.
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 1);
    ldap_set_rebind_proc($ldap, array($this, 'rebind_callback'));

    // Bind to new host, assumes initial bind dn has access to the referred servers.
    if (!ldap_bind($ldap, $this->bind_dn, $this->bind_passwd)) {
      echo "Could not bind to referral server: $referral";
      return 1;
    }
    return 0;
  }

}
