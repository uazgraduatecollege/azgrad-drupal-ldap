<?php

namespace Drupal\ldap_user\Helper;

use Drupal\ldap_user\LdapUserAttributesInterface;

/**
 *
 */
class LdapConfiguration implements LdapUserAttributesInterface {

  /**
   * Returns all synchronization events available from ldap_user.
   *
   * @return array
   *   Available events.
   */
  public static function getAllEvents() {
    return [
      self::EVENT_CREATE_DRUPAL_USER,
      self::EVENT_SYNC_TO_DRUPAL_USER,
      self::EVENT_CREATE_LDAP_ENTRY,
      self::EVENT_SYNC_TO_LDAP_ENTRY,
      self::EVENT_LDAP_ASSOCIATE_DRUPAL_USER,
    ];
  }

  /**
   *
   */
  public static function provisionsDrupalEvents() {
    return [
      self::EVENT_CREATE_DRUPAL_USER => t('On Drupal User Creation'),
      self::EVENT_SYNC_TO_DRUPAL_USER => t('On Sync to Drupal User'),
    ];
  }

  /**
   *
   */
  public static function provisionsDrupalAccountsFromLdap() {
    if (\Drupal::config('ldap_user.settings')->get('drupalAcctProvisionServer') &&
      count(array_filter(array_values(\Drupal::config('ldap_user.settings')->get('drupalAcctProvisionTriggers')))) > 0) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * @param $trigger
   *
   * @return bool
   */
  public static function provisionAvailableToLDAP($trigger) {
    if (\Drupal::config('ldap_user.settings')->get('ldapEntryProvisionTriggers')) {
      return in_array($trigger, \Drupal::config('ldap_user.settings')->get('ldapEntryProvisionTriggers'));
    }
    else {
      return FALSE;
    }
  }

  /**
   * @param $trigger
   *
   * @return bool
   */
  public static function provisionAvailableToDrupal($trigger) {
    if (\Drupal::config('ldap_user.settings')->get('drupalAcctProvisionTriggers')) {
      return in_array($trigger, \Drupal::config('ldap_user.settings')->get('drupalAcctProvisionTriggers'));
    }
    else {
      return FALSE;
    }
  }

}
