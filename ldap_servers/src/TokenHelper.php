<?php

/**
 * @file
 * Contains \Drupal\ldap_servers\TokenHelper.
 */

namespace Drupal\ldap_servers;

/**
 * Temporary helper since TokenFunctions are a trait and there are legacy calls,
 * for example in ldap_user.module, which require TokenFunctions.
 */
class TokenHelper {

  use \Drupal\ldap_servers\TokenFunctions;

}
