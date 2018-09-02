<?php

namespace Drupal\ldap_user\Processor;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\State\StateInterface;
use Drupal\externalauth\Authmap;
use Drupal\ldap_query\Controller\QueryController;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\ldap_servers\ServerFactory;
use Drupal\user\Entity\User;

/**
 * Provides functionality to generically update existing users.
 */
class GroupUserUpdateProcessor {

  protected $queryController;

  protected $logger;
  protected $detailLog;
  protected $config;
  protected $factory;
  protected $state;
  protected $moduleHandler;
  protected $entityTypeManager;
  protected $externalAuth;

  /**
   * Constructor for update process.
   */
  public function __construct(LoggerChannelInterface $logger, LdapDetailLog $detail_log, ConfigFactory $config, ServerFactory $factory, StateInterface $state, ModuleHandler $module_handler, EntityTypeManager $entity_type_manager, Authmap $external_auth) {
    $this->logger = $logger;
    $this->detailLog = $detail_log;
    $this->config = $config->get('ldap_user.settings');
    $this->ldapServerFactory = $factory;
    $this->ldapDrupalUserProcessor = \Drupal::service('ldap_user.drupal_user_processor');
    $this->ldapServer = $this->ldapServerFactory
      ->getServerByIdEnabled($this->config->get('drupalAcctProvisionServer'));
    $this->state = $state;
    $this->moduleHandler = $module_handler;
    $this->entityTypeManager = $entity_type_manager;
    $this->externalAuth = $external_auth;
  }

  /**
   * Check if the query is valid.
   *
   * @return bool
   *   Query valid.
   */
  protected function constraintsValid() {
    if (!$this->queryController) {
      $this->logger->error('Configured query for update mechanism cannot be loaded.');
      return FALSE;
    }
    else {
      return TRUE;
    }
  }

  /**
   * Check whether updates are due.
   *
   * @return bool
   *   Whether to update.
   */
  public function updateDue() {
    $lastRun = $this->state->get('ldap_user_cron_last_group_user_update', 1);
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
    if ($this->moduleHandler->moduleExists('ldap_authorization')) {
      // We are not injecting this service properly to avoid forcing this
      // dependency on authorization.
      /** @var \Drupal\authorization\AuthorizationController $authorization_manager */
      $authorization_manager = \Drupal::service('authorization.manager');
      $authorization_manager->setUser($user);
      $authorization_manager->setAllProfiles();
    }
  }

  /**
   * Runs the updating mechanism.
   *
   * @param string $id
   *   LDAP QueryEntity ID.
   */
  public function runQuery($id) {

    // FIXME: DI.
    $this->queryController = new QueryController($id);
    if (!$this->constraintsValid()) {
      return;
    }

    // @TODO: Batch users as OrphanProcessor does.
    $this->queryController->execute();
    $accountsToProcess = $this->queryController->getRawResults();
    $attribute = $this->ldapServer->get('user_attr');
    $this->logger->notice('Processing @count accounts for periodic update.',
        ['@count' => $accountsToProcess['count']]
      );

    foreach ($accountsToProcess as $account) {
      if (isset($account[$attribute], $account[$attribute][0])) {
        $username = $account[$attribute][0];
        $match = $this->ldapServer->matchUsernameToExistingLdapEntry($username);
        if ($match) {
          $uid = $this->externalAuth->getUid($username, 'ldap_user');
          if ($uid) {
            $drupalAccount = $this->entityTypeManager->getStorage('user')->load($uid);
            $this->ldapDrupalUserProcessor->drupalUserLogsIn($drupalAccount);
            // Reload since data has changed.
            $drupalAccount = $this->entityTypeManager->getStorage('user')->load($drupalAccount->id());
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
              $drupalAccount = $this->entityTypeManager->getStorage('user')->load($drupalAccount->id());
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
    $this->state->set('ldap_user_cron_last_group_user_update', strtotime('today'));
  }

}
