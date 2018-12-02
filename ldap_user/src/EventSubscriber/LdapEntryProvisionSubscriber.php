<?php

namespace Drupal\ldap_user\EventSubscriber;

use Drupal\ldap_servers\Entity\Server;
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
    $events[LdapUserLoginEvent::EVENT_NAME] = ['login'];
    $events[LdapNewUserCreatedEvent::EVENT_NAME] = ['userCreated'];
    $events[LdapUserUpdatedEvent::EVENT_NAME] = ['userUpdated'];
    return $events;
  }

  /**
   * Handle account login with LDAP entry provisioning.
   *
   * @param \Drupal\ldap_user\Event\LdapUserLoginEvent $event
   *   Event.
   */
  public function login(LdapUserLoginEvent $event) {
    $triggers = $this->config->get('ldapEntryProvisionTriggers');
    if ($this->provisionLdapEntriesFromDrupalUsers() && in_array(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION, $triggers)) {
      if (!$this->checkExistingLdapEntry($event->account)) {
        // This should only be necessary if the entry was deleted on the
        // directory server.
        $this->provisionLdapEntry($event->account);
      }
      else {
        $this->syncToLdapEntry($event->account);
      }
    }
  }

  /**
   * Create or update LDAP entries on user update.
   *
   * TODO: Make sure we are not working on excluded accounts, see also
   * other events.
   *
   * @param \Drupal\ldap_user\Event\LdapUserUpdatedEvent $event
   *   Event.
   */
  public function userUpdated(LdapUserUpdatedEvent $event) {
    if ($this->provisionLdapEntriesFromDrupalUsers()) {
      if (isset($this->config->get('ldapEntryProvisionTriggers')[self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE])) {
        if (!$this->checkExistingLdapEntry($event->account)) {
          // This should only be necessary if the entry was deleted on the
          // directory server.
          $this->provisionLdapEntry($event->account);
        }
        else {
          $this->syncToLdapEntry($event->account);
        }
      }
    }
  }

  /**
   * Create or update LDAP entries on user creation.
   *
   * @param \Drupal\ldap_user\Event\LdapNewUserCreatedEvent $event
   *   Event.
   */
  public function userCreated(LdapNewUserCreatedEvent $event) {
    if ($this->provisionLdapEntriesFromDrupalUsers()) {
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

    if (empty($entry->getDn())) {
      $this->detailLog->log('Failed to derive DN.', [], 'ldap_user');
      return FALSE;
    }

    if (empty($entry->getAttributes())) {
      $this->detailLog->log('No attributes defined in mappings.', [], 'ldap_user');
      return FALSE;
    }

    // Stick $proposedLdapEntry in $ldapEntries array for drupal_alter.
    $context = [
      'action' => 'add',
      'corresponding_drupal_data_type' => 'user',
      'account' => $account,
    ];
    $this->moduleHandler->alter('ldap_entry_pre_provision', $entry, $ldap_server, $context);
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
   * Save provisioning entries to database.
   *
   * Need to store <sid>|<dn> in ldap_user_prov_entries field, which may
   *  contain more than one.
   *
   * @param \Drupal\user\UserInterface $account
   * @param \Drupal\ldap_servers\Entity\Server $ldap_server
   * @param \Symfony\Component\Ldap\Entry $entry
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
   * @param \Drupal\user\UserInterface $account
   */
  protected function checkExistingLdapEntry(UserInterface $account) {
    $authmap = \Drupal::service('externalauth.authmap')->get($account->id(), 'ldap_user');
    if ($authmap) {
      $this->ldapUserManager->queryAllBaseDnLdapForUsername($authmap);
    }
  }

}
