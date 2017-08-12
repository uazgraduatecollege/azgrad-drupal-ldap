<?php

namespace Drupal\ldap_servers;

use Drupal\user\Entity\User;

/**
 * Locates potential orphan user accounts.
 */
class OrphanProcessor {

  private $config;
  private $emailList;
  private $ldapQueryOrLimit = 30;
  private $missingServerSemaphore = [];

  /**
   * Constructor.
   */
  public function __construct() {
    $this->config = \Drupal::config('ldap_user.settings')->get();
  }

  /**
   * Check for Drupal accounts which no longer have a related LDAP entry.
   *
   * @return bool
   *   FALSE on error or incompletion or TRUE otherwise.
   */
  public function checkOrphans() {

    if (!$this->config['orphanedDrupalAcctBehavior'] ||
      $this->config['orphanedDrupalAcctBehavior'] == 'ldap_user_orphan_do_not_check') {
      return TRUE;
    }
    $uids = $this->fetchUidsToCheck();

    if (!empty($uids)) {
      $processedUsers = [];

      // To avoid query limits, queries are batched by the limit, for example
      // with 175 users and a limit of 30, 6 batches are run.
      $batches = floor(count($uids) / $this->ldapQueryOrLimit) + 1;
      for ($batch = 1; $batch <= $batches; $batch++) {
        $processedUsers += $this->batchQueryUsers($batch, $uids);
      }

      $this->processUser($processedUsers);

      if (count($this->emailList) > 0) {
        $this->sendOrphanedAccountsMail();
      }

      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Create a "binary safe" string for use in LDAP filters.
   *
   * @param string $value
   *   Unsfe string.
   *
   * @return string
   *   Safe string.
   */
  private function binaryFilter($value) {
    $match = '';
    if (preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i', $value)) {
      // Reconstruct proper "memory" order from (MS?) GUID string.
      $hex_string = str_replace('-', '', $value);
      $value = substr($hex_string, 6, 2) . substr($hex_string, 4, 2) .
        substr($hex_string, 2, 2) . substr($hex_string, 0, 2) .
        substr($hex_string, 10, 2) . substr($hex_string, 8, 2) .
        substr($hex_string, 14, 2) . substr($hex_string, 12, 2) .
        substr($hex_string, 16, 4) . substr($hex_string, 20, 12);
    }

    for ($i = 0; $i < strlen($value); $i = $i + 2) {
      $match .= '\\' . substr($value, $i, 2);
    }

    return $match;
  }

  /**
   * Send email.
   */
  public function sendOrphanedAccountsMail() {
    $mailManager = \Drupal::service('plugin.manager.mail');
    $to = \Drupal::config('system.site')->get('mail');
    $siteLanguage = \Drupal::languageManager()->getCurrentLanguage()->getId();
    $params = ['accounts' => $this->emailList];
    $result = $mailManager->mail('ldap_user', 'orphaned_accounts', $to, $siteLanguage, $params, NULL, TRUE);
    if (!$result) {
      \Drupal::logger('ldap_user')->error('Could not send orphaned LDAP accounts notification.');
    }
  }

  /**
   * Batch query for users.
   *
   * @param int $batch
   *   Batch number.
   * @param array $uids
   *   UIDs to process.
   *
   * @return array
   *   Queried batch of users.
   */
  private function batchQueryUsers($batch, array $uids) {

    $factory = \Drupal::service('ldap.servers');
    /** @var \Drupal\ldap_servers\ServerFactory $factory */
    $servers = $factory->getEnabledServers();

    $users = [];

    // Creates a list of users in the required format.
    $start = ($batch - 1) * $this->ldapQueryOrLimit;
    $end_plus_1 = min(($batch) * $this->ldapQueryOrLimit, count($uids));
    $batch_uids = array_slice($uids, $start, ($end_plus_1 - $start));

    $accounts = User::loadMultiple($batch_uids);
    $filters = [];

    foreach ($accounts as $uid => $user) {
      /** @var \Drupal\user\Entity\User $user */
      $serverId = $user->get('ldap_user_puid_sid')->value;
      $persistentUid = $user->get('ldap_user_puid')->value;
      $persistentUidProperty = $user->get('ldap_user_puid_property')->value;
      if ($serverId && $persistentUid && $persistentUidProperty) {
        if ($servers[$serverId]->get('unique_persistent_attr_binary')) {
          $filters[$serverId][$persistentUidProperty][] = "($persistentUidProperty=" . $this->binaryFilter($persistentUid) . ")";
        }
        else {
          $filters[$serverId][$persistentUidProperty][] = "($persistentUidProperty=$persistentUid)";
        }
        $users[$serverId][$persistentUidProperty][$persistentUid]['uid'] = $uid;
        $users[$serverId][$persistentUidProperty][$persistentUid]['exists'] = FALSE;
      }
      else {
        \Drupal::logger('ldap_user')->notice(
          'User %uid has missing LDAP data fields.',
          ['%uid' => $uid]
        );
      }
    }

    // Query LDAP and update the prepared users with the actual state.
    foreach ($filters as $serverId => $persistentUidAttributes) {
      if (!isset($servers[$serverId])) {
        if (!isset($this->missingServerSemaphore[$serverId])) {
          \Drupal::logger('ldap_user')
            ->error('Server %id not enabled, but needed to remove orphaned LDAP users', ['%id' => $serverId]);
          $this->missingServerSemaphore[$serverId] = TRUE;
        }
        continue;
      }
      foreach ($persistentUidAttributes as $persistentUidProperty => $orElement) {
        // Query should look like (|(guid=3243243)(guid=3243243)(guid=3243243))
        $ldapFilter = '(|' . implode("", $orElement) . ')';
        $ldapEntries = $servers[$serverId]->searchAllBaseDns($ldapFilter, [$persistentUidProperty]);
        if ($ldapEntries === FALSE) {
          // If the query returns an error, ignore the entire server.
          unset($users[$serverId]);
          \Drupal::logger('ldap_user')->error('LDAP server %id had error while querying to deal with orphaned LDAP user entries. Please check that the LDAP server is configured correctly',
            ['%id' => $serverId]
          );
          continue;
        }

        unset($ldapEntries['count']);
        foreach ($ldapEntries as $ldap_entry) {
          $persistentUid = $servers[$serverId]->userPuidFromLdapEntry($ldap_entry);
          $users[$serverId][$persistentUidProperty][$persistentUid]['exists'] = TRUE;
        }
      }
    }
    return $users;
  }

  /**
   * Fetch UIDs to check.
   *
   * @return array
   *   All relevant UID.
   */
  private function fetchUidsToCheck() {
    // We want to query Drupal accounts, which are LDAP associated where a DN
    // is present. The lastUidChecked is used to process only a limited number
    // of batches in the cron run and each user is only checked if the time
    // configured for checking has lapsed.
    $lastUidChecked = \Drupal::state()
      ->get('ldap_user_cron_last_uid_checked', 1);

    $query = \Drupal::entityQuery('user')
      ->exists('ldap_user_current_dn')
      ->condition('uid', $lastUidChecked, '>')
      ->sort('uid', 'ASC')
      ->range(0, $this->config['orphanedCheckQty']);

    $group = $query->orConditionGroup();
    $group->notExists('ldap_user_last_checked');

    switch ($this->config['orphanedAccountCheckInterval']) {
      case 'always':
        $group->condition('ldap_user_last_checked', time(), '<');
        break;

      case 'daily':
        $group->condition('ldap_user_last_checked', strtotime('today'), '<');
        break;

      case 'weekly':
      default:
        $group->condition('ldap_user_last_checked', strtotime('today - 7 days'), '<');
        break;

      case 'monthly':
        $group->condition('ldap_user_last_checked', strtotime('today - 30 days'), '<');
        break;
    }
    $query->condition($group);
    $uids = $query->execute();

    if (count($uids) < $this->config['orphanedCheckQty']) {
      \Drupal::state()->set('ldap_user_cron_last_uid_checked', 1);
    }
    else {
      \Drupal::state()->set('ldap_user_cron_last_uid_checked', max($uids));
    }

    return $uids;
  }

  /**
   * Process one user.
   *
   * @param array $users
   *   User to process.
   */
  private function processUser(array $users) {
    foreach ($users as $serverId => $persistentAttributes) {
      foreach ($persistentAttributes as $attribute => $persistentUids) {
        foreach ($persistentUids as $persistentUid => $user_data) {
          if (isset($user_data['uid'])) {
            $account = User::load($user_data['uid']);
            $account->set('ldap_user_last_checked', time());
            $account->save();
            global $base_url;
            if (!$user_data['exists']) {
              switch ($this->config['orphanedDrupalAcctBehavior']) {
                case 'ldap_user_orphan_email';
                  $this->emailList[] = $account->getAccountName() . "," . $account->getEmail() . "," . $base_url . "/user/" . $user_data['uid'] . "/edit";
                  break;

                case 'user_cancel_block':
                case 'user_cancel_block_unpublish':
                case 'user_cancel_reassign':
                case 'user_cancel_delete':
                  _user_cancel([], $account, $this->config['orphanedDrupalAcctBehavior']);
                  break;
              }
            }
          }
        }
      }
    }
  }

}
