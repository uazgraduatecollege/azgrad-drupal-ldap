<?php

declare(strict_types = 1);

namespace Drupal\ldap_user\Processor;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\State\StateInterface;
use Drupal\externalauth\Authmap;
use Drupal\ldap_query\Controller\QueryController;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\user\Entity\User;
use Psr\Log\LoggerInterface;

/**
 * Provides functionality to generically update existing users.
 */
class GroupUserUpdateProcessor {

  /**
   * Logger.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * Detail log.
   *
   * @var \Drupal\ldap_servers\Logger\LdapDetailLog
   */
  protected $detailLog;

  /**
   * Config.
   *
   * @var \Drupal\Core\Config\Config|\Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * State.
   *
   * @var \Drupal\Core\State\StateInterface
   */
  protected $state;

  /**
   * Module handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandler
   */
  protected $moduleHandler;

  /**
   * Entity Type Manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * Externalauth.
   *
   * @var \Drupal\externalauth\Authmap
   */
  protected $externalAuth;

  /**
   * Query controller.
   *
   * @var \Drupal\ldap_query\Controller\QueryController
   */
  protected $queryController;

  /**
   * Drupal user processor.
   *
   * @var \Drupal\ldap_user\Processor\DrupalUserProcessor
   */
  protected $drupalUserProcessor;

  /**
   * LDAP Server.
   *
   * @var \Drupal\ldap_servers\Entity\Server|null
   */
  protected $ldapServer;

  /**
   * Constructor for update process.
   *
   * @param \Psr\Log\LoggerInterface $logger
   *   Logger.
   * @param \Drupal\ldap_servers\Logger\LdapDetailLog $detail_log
   *   Detail log.
   * @param \Drupal\Core\Config\ConfigFactory $config
   *   Config factory.
   * @param \Drupal\Core\State\StateInterface $state
   *   State.
   * @param \Drupal\Core\Extension\ModuleHandler $module_handler
   *   Module handler.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   Entity type manager.
   * @param \Drupal\externalauth\Authmap $external_auth
   *   Externalauth.
   * @param \Drupal\ldap_query\Controller\QueryController $query_controller
   *   Query controller.
   * @param \Drupal\ldap_user\Processor\DrupalUserProcessor $drupal_user_processor
   *   Drupal user processor.
   */
  public function __construct(
    LoggerInterface $logger,
    LdapDetailLog $detail_log,
    ConfigFactory $config,
    StateInterface $state,
    ModuleHandler $module_handler,
    EntityTypeManagerInterface $entity_type_manager,
    Authmap $external_auth,
    QueryController $query_controller,
    DrupalUserProcessor $drupal_user_processor) {
    $this->logger = $logger;
    $this->detailLog = $detail_log;
    $this->config = $config->get('ldap_user.settings');
    $this->drupalUserProcessor = $drupal_user_processor;
    $this->state = $state;
    $this->moduleHandler = $module_handler;
    $this->entityTypeManager = $entity_type_manager;
    $this->externalAuth = $external_auth;
    $this->queryController = $query_controller;

    $this->ldapServer = $this->entityTypeManager
      ->getStorage('ldap_server')
      ->load($this->config->get('drupalAcctProvisionServer'));
  }

  /**
   * Check if the query is valid.
   *
   * @return bool
   *   Query valid.
   */
  protected function constraintsValid(): bool {
    if (!$this->queryController) {
      $this->logger->error('Configured query for update mechanism cannot be loaded.');
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Check whether updates are due.
   *
   * @return bool
   *   Whether to update.
   */
  public function updateDue(): bool {
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
  private function updateAuthorizations(User $user): void {
    if ($this->moduleHandler->moduleExists('ldap_authorization')) {
      // We are not injecting this service properly to avoid forcing this
      // dependency on authorization.
      /** @var \Drupal\authorization\AuthorizationController $authorization_manager */
      // phpcs:ignore
      $authorization_manager = \Drupal::service('authorization.manager');
      $authorization_manager->setUser($user);
      $authorization_manager->setAllProfiles();
    }
    else {
      // We are saving here for sites without ldap_authorization since saving is
      // embedded in setAllProfiles().
      // TODO: Provide method for decoupling saving users and use it instead.
      $user->save();
    }
  }

  /**
   * Runs the updating mechanism.
   *
   * @param string $id
   *   LDAP QueryEntity ID.
   */
  public function runQuery(string $id): void {

    $this->queryController->load($id);
    if (!$this->constraintsValid()) {
      return;
    }

    // @TODO: Batch users as OrphanProcessor does.
    $this->queryController->execute();
    $accounts_to_process = $this->queryController->getRawResults();
    $attribute = $this->ldapServer->getAuthenticationNameAttribute();
    $this->logger->notice(
      'Processing @count accounts for periodic update.',
        ['@count' => count($accounts_to_process)]
      );

    $user_storage = $this->entityTypeManager->getStorage('user');
    foreach ($accounts_to_process as $account) {
      if ($account->hasAttribute($attribute)) {
        $username = $account->getAttribute($attribute)[0];
        // TODO: Broken.
        $match = $this->drupalUserProcessor->drupalUserExists($username);
        if ($match) {
          $uid = $this->externalAuth->getUid($username, 'ldap_user');
          if ($uid) {
            /** @var \Drupal\user\Entity\User $drupal_account */
            $drupal_account = $user_storage->load($uid);
            $this->drupalUserProcessor->drupalUserLogsIn($drupal_account);
            // Reload since data has changed.
            $drupal_account = $user_storage->load($drupal_account->id());
            $this->updateAuthorizations($drupal_account);
            $this->detailLog->log(
              'Periodic update: @name updated',
              ['@name' => $username],
              'ldap_user'
            );
          }
          else {
            $result = $this->drupalUserProcessor
              ->createDrupalUserFromLdapEntry(['name' => $username, 'status' => TRUE]);
            if ($result) {
              $drupal_account = $this->drupalUserProcessor->getUserAccount();
              $this->drupalUserProcessor->drupalUserLogsIn($drupal_account);
              // Reload since data has changed.
              $drupal_account = $user_storage->load($drupal_account->id());
              $this->updateAuthorizations($drupal_account);
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
