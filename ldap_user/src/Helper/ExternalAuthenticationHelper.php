<?php

namespace Drupal\ldap_user\Helper;


class ExternalAuthenticationHelper {

  /**
   * Replaces the authmap table retired in Drupal 8
   * Drupal 7: user_set_authmap.
   */
  public static function setUserIdentifier($account, $identifier) {
    $authmap = \Drupal::service('externalauth.authmap');
    $authmap->save($account, 'ldap_user', $identifier);
  }

  /**
   * Called from hook_user_delete ldap_user_user_delete.
   */
  public static function deleteUserIdentifier($uid) {
    $authmap = \Drupal::service('externalauth.authmap');
    $authmap->delete($uid);
  }

  /**
   * Replaces the authmap table retired in Drupal 8.
   */
  public static function getUidFromIdentifierMap($identifier) {
    $externalauth = \Drupal::service('externalauth.externalauth');
    $externalauth->load($identifier, 'ldap_user');
    if (property_exists($externalauth, 'uid')) {
      return $externalauth->uid;
    }
  }

  /**
   * Replaces the authmap table retired in Drupal 8.
   */
  public static function getUserIdentifierFromMap($uid) {
    $authmap = \Drupal::service('externalauth.authmap');
    $authdata = $authmap->getAuthdata($uid, 'ldap_user');
    if (isset($authdata['authname']) && !empty($authdata['authname'])) {
      return $authdata['authname'];
    }
  }

  /**
   * @param \Drupal\user\Entity\User $account
   *   A drupal user object.
   *
   * @return boolean TRUE if user should be excluded from ldap provision/syncing
   */
  public static function excludeUser($account = NULL) {
    // Always exclude user 1.
    if (is_object($account) && $account->id() == 1) {
      return TRUE;
    }
    // Exclude users who have been manually flagged as excluded.
    if (is_object($account) && $account->get('ldap_user_ldap_exclude')->value == 1) {
      return TRUE;
    }
    // Everyone else is fine.
    return FALSE;
  }
}