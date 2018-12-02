<?php

namespace Drupal\ldap_user\EventSubscriber;

use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_user\Event\LdapNewUserCreatedEvent;
use Drupal\ldap_user\Event\LdapUserLoginEvent;
use Drupal\ldap_user\Event\LdapUserUpdatedEvent;
use Drupal\user\UserInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Event subscribers for creating and updating LDAP entries.
 */
class LdapEntryProvisionSubscriber extends LdapEntryBaseSubscriber {

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[LdapNewUserCreatedEvent::EVENT_NAME] = ['provisionLdapEntryOnUserCreation'];
    $events[LdapUserLoginEvent::EVENT_NAME] = ['loginLdapEntryProvisioning'];
    $events[LdapUserUpdatedEvent::EVENT_NAME] = ['provisionLdapEntryOnUserUpdated'];
    return $events;
  }

  /**
   * TODO: Make sure we are not working on excluded accounts.
   */
  public function provisionLdapEntryOnUserUpdated(LdapUserUpdatedEvent $event) {
  }

  /**
   * Handle account login with LDAP entry provisioning.
   *
   * @deprecated move one level down
   */
  public function loginLdapEntryProvisioning(LdapUserLoginEvent $event) {
    $triggers = $this->config->get('ldapEntryProvisionTriggers');
    if ($this->provisionsLdapEntriesFromDrupalUsers() && in_array(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION, $triggers)) {
      // TODO: Inject.
      $authmap = \Drupal::service('externalauth.authmap');
      $authname = $authmap->get($event->account->id(), 'ldap_user');
      if (!$this->ldapUserManager->checkDnExists($authname)) {
        $this->provisionLdapEntry($event->account);
      }
      else {
        $this->syncToLdapEntry($event->account);
      }
    }
  }

  /**
   * This method is called whenever the ldap_new_drupal_user_created event is
   * dispatched.
   *
   * @TODO: Wrong event passed.
   */
  public function provisionLdapEntryOnUserCreation(LdapNewUserCreatedEvent $event) {
    if ($this->provisionsLdapEntriesFromDrupalUsers()) {
      if (isset($this->config->get('ldapEntryProvisionTriggers')[self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE])) {
        if (!$this->checkExistingLdapEntry($event->account)) {
          $this->provisionLdapEntry($event->account);
        }
        else {
          $this->syncToLdapEntry($event->account);
        }
      }
    }
  }

  /**
   * Provision an LDAP entry if none exists.
   *
   * If one exists do nothing, takes Drupal user as argument.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal user.
   * @param array $ldap_user
   *   LDAP user as pre-populated LDAP entry. Usually not provided.
   *
   * @return bool
   *   Provisioning successful.
   */
  protected function provisionLdapEntry(UserInterface $account) {

    if ($account->isAnonymous()) {
      $this->logger->notice('Cannot provision LDAP user unless corresponding Drupal account exists.');
      return FALSE;
    }

    if (!$this->config->get('ldapEntryProvisionServer')) {
      $this->logger->error('No provisioning server enabled');
      return FALSE;
    }

    /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
    $ldap_server = $this->entityTypeManager
      ->getStorage('ldap_server')
      ->load($this->config->get('ldapEntryProvisionServer'));

    try {
      $entry = $this->buildLdapEntry($account, $ldap_server, self::EVENT_CREATE_LDAP_ENTRY);
    }
    catch (\Exception $e) {
      $this->logger->error('User or server is missing during LDAP provisioning: %message', ['%message', $e->getMessage()]);
      return FALSE;
    }

    $proposed_dn_lowercase = mb_strtolower($entry->getDn());

    if (empty($entry->getDn())) {
      $this->detailLog->log('Failed to derive dn and or mappings', [], 'ldap_user');
      return FALSE;
    }

    // Stick $proposedLdapEntry in $ldapEntries array for drupal_alter.
    $context = [
      'action' => 'add',
      'corresponding_drupal_data' => [$proposed_dn_lowercase => $account],
      'corresponding_drupal_data_type' => 'user',
      'account' => $account,
    ];
    $this->moduleHandler->alter('ldap_entry_pre_provision', $entry, $ldap_server, $context);
    // Remove altered $proposedLdapEntry from $ldapEntries array.
    $this->ldapUserManager->setServer($ldap_server);
    if ($this->ldapUserManager->createLdapEntry($entry)) {
      $callback_params = [$entry, $ldap_server, $context];
      $this->moduleHandler->invokeAll('ldap_entry_post_provision', $callback_params);
      $this->updateUserProvisioningReferences($account, $ldap_server, $entry);

    }
    else {
      $this->logger->error('LDAP entry for @username cannot be created on @sid not created because of an error. Proposed DN: %dn)',
        [
          '%dn' => $entry->getDn(),
          '@sid' => $ldap_server->id(),
          '@username' => @$account->getAccountName(),
        ]);
      return FALSE;
    }

    $this->detailLog->log(
      'LDAP entry for @username on server @sid created for DN %dn.',
      [
        '%dn' => $entry->getDn(),
        '@sid' => $ldap_server->id(),
        '@username' => @$account->getAccountName(),
      ],
      'ldap_user'
    );

    return TRUE;
  }

  /**
   * Update LDAP Entry event.
   *
   * @param \Drupal\ldap_user\Event\LdapUserUpdatedEvent $event
   *   todo: needed?
   */
  public function updateLdapEntry(LdapUserUpdatedEvent $event) {
    /** @var \Drupal\user\Entity\User $account */
    $account = $event->account;
    // TODO: Check 3.x to see if we introduced a bug here.
    if ($this->ldapEntryProvisionValid($account->getAccountName())) {
      $this->syncToLdapEntry($account);
    }
  }

  /**
   * Should we update the LDAP entry?
   *
   * @param $account_name
   *   Drupal user name.
   *
   * @return bool
   *   Provision.
   *   todo: needed?
   */
  private function ldapEntryProvisionValid($account_name) {
    $triggers = $this->config->get('ldapEntryProvisionTriggers');
    if ($this->provisionsLdapEntriesFromDrupalUsers() && in_array(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION, $triggers)) {
      return TRUE;
    }
    return FALSE;
  }


  /**
   * @param \Drupal\user\UserInterface $account
   */
  protected function checkExistingLdapEntry(UserInterface $account) {
    $authmap = \Drupal::service('externalauth.authmap')->get($account->id(), 'ldap_user');
    if ($authmap) {
      $this->ldapUserManager->queryAllBaseDnLdapForUsername($authmap);
    }
  }

  /**
   * Given a Drupal account, sync to related LDAP entry.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal user object.
   */
  public function syncToLdapEntry(UserInterface $account) {
    if (!$this->config->get('ldapEntryProvisionServer')) {
      $this->logger->error('Provisioning server not available');
      return;
    }

    /** @var \Drupal\ldap_servers\Entity\Server $server */
    $server = $this->entityTypeManager
      ->getStorage('ldap_server')
      ->load($this->config->get('ldapEntryProvisionServer'));

    try {
      $entry = $this->buildLdapEntry($account, $server, self::EVENT_SYNC_TO_LDAP_ENTRY);
    }
    catch (\Exception $e) {
      $this->logger->error('Unable to prepare LDAP entry: %message', ['%message', $e->getMessage()]);
      return;
    }

    if (!empty($entry->getDn())) {
      // Stick $proposedLdapEntry in $ldap_entries array for drupal_alter.
      $proposed_dn_lower_case = mb_strtolower($entry->getDn());
      $context = [
        'action' => 'update',
        'corresponding_drupal_data_type' => 'user',
        'account' => $account,
      ];
      $this->moduleHandler->alter('ldap_entry_pre_provision', $entry, $server, $context);
      $this->ldapUserManager->modifyLdapEntry($entry);
      $params = [$entry, $server, $context];
      $this->moduleHandler->invokeAll('ldap_entry_post_provision', $params);
      $tokens = [
        '%dn' => $entry->getDn(),
        '%sid' => $this->config->get('ldapEntryProvisionServer'),
        '%username' => $account->getAccountName(),
        '%uid' => (!method_exists($account, 'id') || empty($account->id())) ? '' : $account->id(),
      ];
      $this->logger->info('LDAP entry on server %sid synced dn=%dn for username=%username, uid=%uid', $tokens);
    }
  }

  /**
   * Save provisioning entries to database.
   *
   * Need to store <sid>|<dn> in ldap_user_prov_entries field, which may
   *  contain more than one.
   * @param \Drupal\user\UserInterface $account
   * @param Server $ldap_server
   * @param Entry $entry
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   */
  protected function updateUserProvisioningReferences(
    UserInterface $account,
    Server $ldap_server,
    Entry $entry
  ) {
    $ldap_user_prov_entry = $ldap_server->id() . '|' . $entry->getDn();
    if (NULL !== $account->get('ldap_user_prov_entries')) {
      $account->set('ldap_user_prov_entries', []);
    }
    $ldap_user_provisioning_entry_exists = FALSE;
    if ($account->get('ldap_user_prov_entries')->value) {
      foreach ($account->get('ldap_user_prov_entries')->value as $field_value_instance) {
        if ($field_value_instance == $ldap_user_prov_entry) {
          $ldap_user_provisioning_entry_exists = TRUE;
        }
      }
    }
    if (!$ldap_user_provisioning_entry_exists) {
      $prov_entries = $account->get('ldap_user_prov_entries')->value;
      $prov_entries[] = [
        'value' => $ldap_user_prov_entry,
        'format' => NULL,
        'save_value' => $ldap_user_prov_entry,
      ];
      $account->set('ldap_user_prov_entries', $prov_entries);
      $account->save();
    }
  }

}
