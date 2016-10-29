<?php

/**
 * @file
 * Cron relate functions.
 */

use Drupal\Core\Language\Language;
/**
 * Function to respond to ldap associated drupal accounts which no
 * longer have a related LDAP entry.
 *
 * @param LdapUserConf $ldap_user_conf
 *
 * @return boolean FALSE on error or incompletion or TRUE otherwise
 *
 * @todo need to avoid sending repeated emails
 */
function _ldap_user_orphans($ldap_user_conf) {

  // Return TRUE; // this is untested code.
  if (!$ldap_user_conf->orphanedDrupalAcctBehavior ||
    $ldap_user_conf->orphanedDrupalAcctBehavior == 'ldap_user_orphan_do_not_check') {
    return TRUE;
  }

  /**
   * query drupal accounts
   *   - ldap associated drupal accounts
   *   - where (ldap_user_current_dn not null)
   *   - ordered by ldap_user_last_checked
   *   - order by uid asc (get oldest first)
   */

  $last_uid_checked = \Drupal::config('ldap_user.settings')->get('cron_last_uid_checked');

  // @FIXME : replace by D8 entityQuery
  // https://www.drupal.org/node/1827278
  // $query = new EntityFieldQuery();
  // $query->entityCondition('entity_type', 'user')
  //   ->fieldCondition('ldap_user_current_dn', 'value', 'NULL', '!=')
  //   ->propertyCondition('uid', $last_uid_checked, '>')
  //   ->propertyOrderBy('uid', 'ASC')
  //   ->range(0, $ldap_user_conf->orphanedCheckQty - 1)
  //   ->addMetaData('account', \Drupal::entityManager()->getStorage('user')->load(1)); // run the query as user 1
  // $result = $query->execute();
  $drupal_users = array();
  $ldap_servers = ldap_servers_get_servers(NULL, 'enabled');
  $watchdogs_sids_missing_watchdogged = array();
  /**
   * first produce array of form:
   *  $drupal_users[$sid][$puid_attr][$puid]['exists'] = FALSE | TRUE;
   *  signifying if corresponding LDAP Entry exists
   */
  if (!(isset($result['user']) && count($result['user']) > 0)) {
    return TRUE;
  }

  $uids = array_keys($result['user']);
  $user_count = count($uids);

  // If maxed out reset uid check counter.
  if ($user_count < $ldap_user_conf->orphanedCheckQty) {
    \Drupal::configFactory()->getEditable('ldap_user.settings')->set('ldap_user_cron_last_uid_checked', 1)->save();
  }
  else {
    \Drupal::configFactory()->getEditable('ldap_user.settings')->set('ldap_user_cron_last_uid_checked', $uids[count($uids) - 1])->save();
  }

  $maxfilter_ors = 30;

  $batches = floor($user_count / $maxfilter_ors) + 1;
  // e.g. 175 users and  50 max ldap query ors will yield 4 batches
  // e.g. 1,2,3,4.
  for ($batch = 1; $batch <= $batches; $batch++) {
    $filters = array();

    /**
     * 1. populate $drupal_users[$sid][$puid_attr][$puid]['exists']  = TRUE
     *
     * e.g.  first batch $i=0; $i<50; $i++
     *       2nd batch   $i=50; $i<100; $i++
     *       4th batch   $i=150; $i<175; $i++
     */
    // e.g 0, 50, 100.
    $start = ($batch - 1) * $maxfilter_ors;
    // e.g. 50, 100, 150.
    $end_plus_1 = min(($batch) * $maxfilter_ors, $user_count);
    // e.g. 50, 50; 100, 50.
    $batch_uids = array_slice($uids, $start, ($end_plus_1 - $start));
    $accounts = \Drupal::entityManager()->getStorage('user');

    foreach ($accounts as $uid => $user) {
      $sid = @$user->ldap_user_puid_sid['und'][0]['value'];
      $puid = @$user->ldap_user_puid['und'][0]['value'];
      $puid_attr = @$user->ldap_user_puid_property['und'][0]['value'];
      if ($sid && $puid && $puid_attr) {
        if ($ldap_servers[$sid]->unique_persistent_attr_binary) {
          $filters[$sid][$puid_attr][] = "($puid_attr=" . ldap_servers_binary_filter($puid) . ")";
        }
        else {
          $filters[$sid][$puid_attr][] = "($puid_attr=$puid)";
        }
        $drupal_users[$sid][$puid_attr][$puid]['uid'] = $uid;
        $drupal_users[$sid][$puid_attr][$puid]['exists'] = FALSE;
      }
      else {
        // User with missing ldap data fields
        // perhaps should be watchdogged?
      }
    }

    // 2. set $drupal_users[$sid][$puid_attr][$puid]['exists'] to FALSE
    // if entry doesn't exist.
    foreach ($filters as $sid => $puid_attrs) {
      if (!isset($ldap_servers[$sid])) {
        if (!isset($watchdogs_sids_missing_watchdogged[$sid])) {
          \Drupal::logger('ldap_user')->error('Server %sid not enabled, but needed to remove orphaned ldap users', array('%sid' => $sid));
          $watchdogs_sids_missing_watchdogged[$sid] = TRUE;
        }
        continue;
      }
      foreach ($puid_attrs as $puid_attr => $ors) {
        // Query should look like (|(guid=3243243)(guid=3243243)(guid=3243243))
        $ldap_filter = '(|' . join("", $ors) . ')';
        $ldap_entries = $ldap_servers[$sid]->searchAllBaseDns($ldap_filter, array($puid_attr));
        if ($ldap_entries === FALSE) {
          // If query has error, don't remove ldap entries!
          unset($drupal_users[$sid]);
          \Drupal::logger('ldap_user')->error('ldap server %sid had error while querying to
            deal with orphaned ldap user entries.  Please check that the ldap
            server is configured correctly.  Query; %query', array('%sid' => $sid, '%query' => $query));
          continue;
        }

        unset($ldap_entries['count']);
        foreach ($ldap_entries as $i => $ldap_entry) {
          $puid = $ldap_servers[$sid]->userPuidFromLdapEntry($ldap_entry);
          $drupal_users[$sid][$puid_attr][$puid]['exists'] = TRUE;
        }
      }
    }
  }
  // 3. we now have $drupal_users[$sid][$puid_attr][$puid]['exists'] = FALSE | TRUE;.
  if ($ldap_user_conf->orphanedDrupalAcctBehavior == 'ldap_user_orphan_email') {
    $email_list = array();
    global $base_url;
  }
  $check_time = time();
  $email_list = array();
  foreach ($drupal_users as $sid => $puid_x_puid_attrs) {
    foreach ($puid_x_puid_attrs as $puid_attr => $puids) {
      foreach ($puids as $puid => $user_data) {
        $account = $accounts[$user_data['uid']];
        $user_edit['ldap_user_last_checked'][Language::LANGCODE_NOT_SPECIFIED][0]['value'] = $check_time;
        $account = user_save($account, $user_edit, 'ldap_user');
        if (!$user_data['exists']) {
          /**
           * $ldap_user_conf->orphanedDrupalAcctBehavior will either be
           *  'ldap_user_orphan_email' or one of the user module options:
           *     user_cancel_block, user_cancel_block_unpublish,
           *     user_cancel_reassign, user_cancel_delete
           */
          if ($ldap_user_conf->orphanedDrupalAcctBehavior == 'ldap_user_orphan_email') {
            $email_list[] = $account->name . "," . $account->mail . "," . $base_url . "/user/$uid/edit";
          }
          else {
            _user_cancel(array(), $account, $ldap_user_conf->orphanedDrupalAcctBehavior);
          }
        }
      }
    }
  }

  if (count($email_list) > 0) {
    $site_email = config('system.site')->get('mail');
    $params = array('accounts' => $email_list);
    if ($site_email) {
      drupal_mail(
        'ldap_user',
        'orphaned_accounts',
        $site_email,
        language_default(),
        $params
      );
    }
  }

  return TRUE;
}
