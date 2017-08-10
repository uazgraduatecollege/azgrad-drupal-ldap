<?php

namespace Drupal\ldap_user\Processor;

use Drupal\authorization\Entity\AuthorizationProfile;
use Drupal\ldap_query\Controller\QueryController;
use Drupal\ldap_servers\ServerFactory;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;
use Drupal\user\Entity\User;

/**
 * Provides functionality to generically update existing users.
 */
class GroupUserUpdateProcessor {

  private $config;
  private $queryController;

  /**
   * Constructor for update process.
   *
   * @param string $id
   *   LDAP QueryEntity ID.
   */
  public function __construct($id) {
    $this->detailedWatchdog = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
    $this->config = \Drupal::config('ldap_user.settings');
    $this->ldapDrupalUserProcessor = new DrupalUserProcessor();
    $this->ldapServerFactory = new ServerFactory();
    $this->ldapServer = $this->ldapServerFactory
      ->getServerByIdEnabled($this->config->get('drupalAcctProvisionServer'));
    $this->queryController = new QueryController($id);

    if (!$this->queryController) {
      \Drupal::logger('ldap_user')
        ->error('Configured query @name is missing for update mechanism.', ['@name' => $id]);
    }
  }

  /**
   * Check whether updates are due.
   *
   * @return bool
   *   Whether to update.
   */
  public function updateDue() {
    $lastRun = \Drupal::state()
      ->get('ldap_user_cron_last_group_user_update', 1);
    $result = FALSE;
    switch ($this->config->get('userUpdateCronInterval')) {
      case 'always':
        $result = TRUE;
        break;

      case 'daily':
        $result = strtotime('today -1 day') - $lastRun >= 0;
        break;

      case 'weekly':
        $result = strtotime('today -7 day') - $lastRun >= 0;
        break;

      case 'monthly':
        $result = strtotime('today -30 day') - $lastRun >= 0;
        break;
    }
    return $result;
  }

  /**
   * Update authorizations.
   *
   * @param \Drupal\user\Entity\User $user
   *   Drupal user to update.
   */
  private function updateAuthorizations(User $user) {
    if (\Drupal::moduleHandler()->moduleExists('ldap_authorization')) {
      // TODO: Duplicated from LoginValidator.
      $profiles = authorization_get_profiles();
      foreach ($profiles as $profile_id) {
        $profile = AuthorizationProfile::load($profile_id);
        if ($profile->getProviderId() == 'ldap_provider') {
          // @TODO: https://www.drupal.org/node/2849865
          module_load_include('inc', 'authorization', 'authorization');
          _authorizations_user_authorizations($user, 'set', $profile_id);
        }
      }
    }
  }

  /**
   * Runs the updating mechanism.
   */
  public function runQuery() {
    // @TODO: Batch users as OrphanProcessor does.
    $this->queryController->execute();
    $accountsToProcess = $this->queryController->getRawResults();
    $attribute = $this->ldapServer->get('user_attr');
    \Drupal::logger('ldap_user')
      ->notice('Processing @count accounts for periodic update.',
        ['@count' => $accountsToProcess['count']]
      );

    foreach ($accountsToProcess as $account) {
      if (isset($account[$attribute], $account[$attribute][0])) {
        $username = $account[$attribute][0];
        $match = $this->ldapServer->matchUsernameToExistingLdapEntry($username);
        if ($match) {
          if (ExternalAuthenticationHelper::getUidFromIdentifierMap($username)) {
            $drupalAccount = User::load(ExternalAuthenticationHelper::getUidFromIdentifierMap($username));
            $this->ldapDrupalUserProcessor->drupalUserLogsIn($drupalAccount);
            $this->updateAuthorizations($drupalAccount);
            if ($this->detailedWatchdog) {
              \Drupal::logger('ldap_user')
                ->notice('Periodic update: @name updated',
                  ['@name' => $username]
                );
            }
          }
          else {
            $drupalAccount = $this->ldapDrupalUserProcessor->provisionDrupalAccount(['name' => $username, 'status' => TRUE]);
            $this->ldapDrupalUserProcessor->drupalUserLogsIn($drupalAccount);
            $this->updateAuthorizations($drupalAccount);
            if ($this->detailedWatchdog) {
              \Drupal::logger('ldap_user')
                ->notice('Periodic update: @name created',
                  ['@name' => $username]
                );
            }
          }
        }
      }
    }
    \Drupal::state()
      ->set('ldap_user_cron_last_group_user_update', strtotime('today'));
  }

}
