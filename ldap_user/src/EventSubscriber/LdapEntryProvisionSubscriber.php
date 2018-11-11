<?php

namespace Drupal\ldap_user\EventSubscriber;

use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_user\Event\LdapNewUserCreatedEvent;
use Drupal\ldap_user\Event\LdapUserLoginEvent;
use Drupal\ldap_user\Event\LdapUserUpdatedEvent;
use Drupal\ldap_user\Exception\LdapBadParamsException;
use Drupal\user\UserInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Class ProvisionLdapEntryOnUserCreation.
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
      // Provision entry.
      // TODO: Is it consistent with 3.x to pass the account_name directly to DN here?
      // FIXME: We need to fix account loading here, would be best the event passed that.
      $account = NULL;
      if (!$this->ldapUserManager->checkDnExists($event->accountName)) {
        $this->provisionLdapEntry($account);
      }
      else {
        $this->syncToLdapEntry($account);
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
  protected function provisionLdapEntry(UserInterface $account, array $ldap_user = NULL) {

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
      $proposed_ldap_entry = $this->drupalUserToLdapEntry($account, $ldap_server, $ldap_user);
    }
    catch (\Exception $e) {
      $this->logger->error('User or server is missing during LDAP provisioning: %message', ['%message', $e->getMessage()]);
      return FALSE;
    }

    if ((is_array($proposed_ldap_entry) && isset($proposed_ldap_entry['dn']) && $proposed_ldap_entry['dn'])) {
      $proposedDn = $proposed_ldap_entry['dn'];
    }
    else {
      $proposedDn = NULL;
    }
    $proposedDnLowercase = mb_strtolower($proposedDn);

    if (!$proposedDn) {
      $this->detailLog->log('Failed to derive dn and or mappings', [], 'ldap_user');
      return FALSE;
    }

    // Stick $proposedLdapEntry in $ldapEntries array for drupal_alter.
    $ldapEntries = [$proposedDnLowercase => $proposed_ldap_entry];
    $context = [
      'action' => 'add',
      'corresponding_drupal_data' => [$proposedDnLowercase => $account],
      'corresponding_drupal_data_type' => 'user',
      'account' => $account,
    ];
    $this->moduleHandler->alter('ldap_entry_pre_provision', $ldapEntries, $ldap_server, $context);
    // Remove altered $proposedLdapEntry from $ldapEntries array.
    $proposed_ldap_entry = new Entry($proposedDn, $ldapEntries[$proposedDnLowercase]);
    $this->ldapUserManager->setServer($ldap_server);
    if ($this->ldapUserManager->createUserEntry($proposed_ldap_entry)) {
      $callbackParams = [$ldapEntries, $ldap_server, $context];
      $this->moduleHandler->invokeAll('ldap_entry_post_provision', $callbackParams);

      // Need to store <sid>|<dn> in ldap_user_prov_entries field, which may
      // contain more than one.
      $ldap_user_prov_entry = $ldap_server->id() . '|' . $proposed_ldap_entry['dn'];
      if (NULL !== $account->get('ldap_user_prov_entries')) {
        $account->set('ldap_user_prov_entries', []);
      }
      $ldapUserProvisioningEntryExists = FALSE;
      if ($account->get('ldap_user_prov_entries')->value) {
        foreach ($account->get('ldap_user_prov_entries')->value as $fieldValueInstance) {
          if ($fieldValueInstance == $ldap_user_prov_entry) {
            $ldapUserProvisioningEntryExists = TRUE;
          }
        }
      }
      if (!$ldapUserProvisioningEntryExists) {
        // @TODO Serialise?
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
    else {
      $this->logger->error('LDAP entry for @username cannot be created on @sid not created because of an error. Proposed DN: %dn)',
        [
          '%dn' => $proposed_ldap_entry->getDn(),
          '@sid' => $ldap_server->id(),
          '@username' => @$account->getAccountName(),
        ]);
      return FALSE;
    }

    $this->detailLog->log(
      'LDAP entry for @username on server @sid created for DN %dn.',
      [
        '%dn' => $proposed_ldap_entry->getDn(),
        '@sid' => $ldap_server->id(),
        '@username' => @$account->getAccountName(),
      ],
      'ldap_user'
    );

    return TRUE;
  }

  /**
   * Populate LDAP entry array for provisioning.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal account.
   * @param \Drupal\ldap_servers\Entity\Server $ldap_server
   *   LDAP server.
   * @param array $params
   *   Parameters with the following key values:
   *   'ldap_context' =>
   *   'function' => function calling function, e.g. 'provisionLdapEntry'
   *   'direction' => self::PROVISION_TO_LDAP || self::PROVISION_TO_DRUPAL.
   * @param array|null $ldap_user_entry
   *   The LDAP user entry.
   *
   * @return array
   *   Array of (ldap entry, $result) in LDAP extension array format.
   *   THIS IS NOT THE ACTUAL LDAP ENTRY.
   *
   * @throws \Drupal\ldap_user\Exception\LdapBadParamsException
   */
  public function drupalUserToLdapEntry(UserInterface $account, Server $ldap_server, $ldap_user_entry = NULL) {
    // @FIXME: This function is incorrectly in LdapEntryBaseSubscriber, too. Only there maybe?
    // @FIXME: prov_event not correctly passed for create (missing in general there)

    if (!$ldap_user_entry) {
      $ldap_user_entry = [];
    }

    if (!is_object($account) || !is_object($ldap_server)) {
      throw new LdapBadParamsException('Missing user or server.');
    }

    $direction = self::PROVISION_TO_LDAP;
    $prov_events = [self::EVENT_CREATE_LDAP_ENTRY];

    // TODO: That event should not really be hardcoded here (or rename the function)
    $mappings = $this->syncMappingHelper->getFieldsSyncedToLdap(self::EVENT_CREATE_LDAP_ENTRY);
    // Loop over the mappings.
    foreach ($mappings as $field_key => $field_detail) {
      list($ldapAttributeName, $ordinal) = $this->extractTokenParts($field_key);
      $ordinal = (!$ordinal) ? 0 : $ordinal;
      if ($ldap_user_entry && isset($ldap_user_entry[$ldapAttributeName]) && is_array($ldap_user_entry[$ldapAttributeName]) && isset($ldap_user_entry[$ldapAttributeName][$ordinal])) {
        // Don't override values passed in.
        continue;
      }

      $synced = $this->syncMappingHelper->isSyncedToLdap($field_key, array_pop($prov_events));
      if ($synced) {
        $token = ($field_detail['user_attr'] == 'user_tokens') ? $field_detail['user_tokens'] : $field_detail['user_attr'];
        $value = $this->tokenProcessor->tokenReplace($account, $token, 'user_account');

        if ($ldapAttributeName == 'dn' && $value) {
          $ldap_user_entry['dn'] = $value;
        }
        elseif ($value) {
          if (!isset($ldap_user_entry[$ldapAttributeName]) || !is_array($ldap_user_entry[$ldapAttributeName])) {
            $ldap_user_entry[$ldapAttributeName] = [];
          }
          $ldap_user_entry[$ldapAttributeName][$ordinal] = $value;
        }
      }
    }

    // Allow other modules to alter $ldap_user.
    $params = [
      'prov_events' => $prov_events,
      'direction' => $direction,
    ];
    $this->moduleHandler->alter('ldap_entry', $ldap_user_entry, $params);

    return $ldap_user_entry;
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

}
