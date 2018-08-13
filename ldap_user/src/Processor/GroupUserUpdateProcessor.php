<?php

namespace Drupal\ldap_user\Processor;

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
   * LDAP details logger.
   *
   * @var \Drupal\ldap_servers\Logger\LdapDetailLog
   */
  protected $detailLog;

  /**
   * Constructor for update process.
   *
   * @param string $id
   *   LDAP QueryEntity ID.
   */
  public function __construct($id) {
    // TODO: Inject services.
    $this->detailLog = \Drupal::service('ldap.detail_log');
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
      /** @var \Drupal\authorization\AuthorizationController $controller */
      $controller = \Drupal::service('authorization.manager');
      $controller->setUser($user);
      $controller->setAllProfiles();
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
            // Reload since data has changed.
            $drupalAccount = User::load($drupalAccount->id());
            $this->updateAuthorizations($drupalAccount);
            $this->detailLog->log(
              'Periodic update: @name updated',
              ['@name' => $username],
              'ldap_user'
            );
          }
          else {
            $result = $this->ldapDrupalUserProcessor
              ->provisionDrupalAccount(['name' => $username, 'status' => TRUE]);
            if ($result) {
              $drupalAccount = $this->ldapDrupalUserProcessor->getUserAccount();
              $this->ldapDrupalUserProcessor->drupalUserLogsIn($drupalAccount);
              // Reload since data has changed.
              $drupalAccount = User::load($drupalAccount->id());
              $this->updateAuthorizations($drupalAccount);
              $this->detailLog->log(
                'Periodic update: @name created',
                ['@name' => $username],
                'ldap_user'
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
