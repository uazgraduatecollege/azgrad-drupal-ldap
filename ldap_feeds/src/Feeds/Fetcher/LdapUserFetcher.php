<?php

/**
 * @file
 * Contains \Drupal\ldap_feeds\Feeds\Fetcher\LdapUserFetcher.
 */

namespace Drupal\ldap_feeds\Feeds\Fetcher;

use Drupal\feeds\FeedInterface;
use Drupal\feeds\Plugin\Type\FeedsPluginInterface;
use Drupal\feeds\StateInterface;
use Drupal\ldap_feeds\Result\LdapFetcherResultInterface;
use Drupal\ldap_feeds\Result\LdapFetcherResult;

/**
 * Defines an LDAP user fetcher.
 *
 * @FeedsFetcher(
 *   id = "ldap_user",
 *   title = @Translation("Drupal User LDAP Entry Fetcher"),
 *   description = @Translation("Retrieves user data for existing LDAP associated accounts."),
 *   configuration_form = "Drupal\ldap_feeds\Feeds\Fetcher\Form\LDAPUserFetcherForm",
 *   arguments = {"@cache.feeds_download", "@file_system"}
 * )
 */
class LDAPUserFetcher extends LDAPFetcher {

  /**
   * {@inheritdoc}
   */
  public function fetch(FeedInterface $feed, StateInterface $state) {
    
    // Needs to loop through all users, and query ldap for each, one at a time.
    $query = \Drupal::entityQuery('user');
    $entities = $query
      ->execute();
    $users = \Drupal\user\Entity\User::loadMultiple(array_keys($entities));
    if ($this->filterRoles) {
      $selectedRoles = array_filter($this->filterRoles);
      $filterOnRoles = (boolean) (count($selectedRoles));
    }
    else {
      $filterOnRoles = FALSE;
    }

    // @TODO wire up the config.
    $this->filterLdapAuthenticated = FALSE;
    
    // This was retired. Did we replace it?
    // $data = $user->data['ldap_user'];
    // error_log('data: ' . $data);

    foreach ($users as $uid => $user) {
      if (
        $uid == 0 ||
        $uid == 1 ||
        ($this->filterLdapAuthenticated && !isset($user->data['ldap_user'])) ||
        ($filterOnRoles && !array_intersect(array_values($selectedRoles), array_keys($user->roles)))
        ) {
        continue;
      }

      if ($ldap_user = ldap_servers_get_user_ldap_data($user)) {
        unset($ldap_user['mail']);
        $ldap_user['attr']['count'] = $ldap_user['attr']['count'] + count($this->availableDrupalUserAttributes);
        foreach ($this->availableDrupalUserAttributes as $attr_name => $attr_conf) {
          $ldap_user['attr'][] = $attr_conf['token'];
          $ldap_user['attr'][$attr_conf['token']]['count'] = 1;
          $ldap_user['attr'][$attr_conf['token']][0] = (string) $user->{$attr_name};
        }

        $results[] = $ldap_user;
      }
    }
    $results['count'] = count($results);
    return new LdapFetcherResult($results);
  }

  /**
   * Overrides parent::getRaw();
   */
  public function getRaw() {

    // needs to loop through all users, and query ldap for each, one at a time

    $query = new EntityFieldQuery;
    $entities = $query
      ->entityCondition('entity_type', 'user')
      ->execute();
    $users = entity_load('user', array_keys($entities['user']));
    if ($this->filterRoles) {
      $selectedRoles = array_filter($this->filterRoles);
      $filterOnRoles = (boolean)(count($selectedRoles));
    }
    else {
      $filterOnRoles = FALSE;
    }


    foreach ($users as $uid => $user) {
      if (
        $uid == 0 ||
        $uid == 1 ||
        ($this->filterLdapAuthenticated && !isset($user->data['ldap_user'])) ||
        ($filterOnRoles && !array_intersect(array_values($selectedRoles), array_keys($user->roles)))
        ) {
        continue;
      }

      if ($ldap_user = ldap_servers_get_user_ldap_data($user)) {
        unset($ldap_user['mail']);
        $ldap_user['attr']['count'] = $ldap_user['attr']['count'] + count($this->availableDrupalUserAttributes);
        foreach ($this->availableDrupalUserAttributes as $attr_name => $attr_conf) {
          $ldap_user['attr'][] = $attr_conf['token'];
          $ldap_user['attr'][$attr_conf['token']]['count'] = 1;
          $ldap_user['attr'][$attr_conf['token']][0] = (string)$user->{$attr_name};
        }

        $results[] = $ldap_user;
      }
    }
    $results['count'] = count($results);
   // drupal_set_message("<pre>" . print_r($results, TRUE));
    return $results;
  }

}
