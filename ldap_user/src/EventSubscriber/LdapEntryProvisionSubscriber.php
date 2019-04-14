<?php

namespace Drupal\ldap_user\EventSubscriber;

use Drupal\ldap_servers\LdapTransformationTraits;
use Drupal\ldap_user\Event\LdapNewUserCreatedEvent;
use Drupal\ldap_user\Event\LdapUserLoginEvent;
use Drupal\ldap_user\Event\LdapUserUpdatedEvent;
use Drupal\user\UserInterface;
use Symfony\Component\Ldap\Entry;
use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\File\FileSystem;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\Helper\CredentialsStorage;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_servers\LdapUserManager;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_user\Exception\LdapBadParamsException;
use Drupal\ldap_user\FieldProvider;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;


/**
 * Event subscribers for creating and updating LDAP entries.
 */
class LdapEntryProvisionSubscriber implements EventSubscriberInterface, LdapUserAttributesInterface {

  use LdapTransformationTraits;

  private $config;

  private $logger;

  private $detailLog;

  private $entityTypeManager;

  private $moduleHandler;

  private $ldapUserManager;

  private $tokenProcessor;

  private $fieldProvider;

  private $fileSystem;

  /**
   * Server.
   *
   * @var \Drupal\ldap_servers\Entity\Server
   */
  private $ldapServer;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactory $config_factory
   *   Config factory.
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   *   Logger.
   * @param \Drupal\ldap_servers\Logger\LdapDetailLog $detail_log
   *   Detail log.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   Entity type manager.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   Module handler.
   * @param \Drupal\ldap_servers\LdapUserManager $ldap_user_manager
   *   LDAP user manager.
   * @param \Drupal\ldap_servers\Processor\TokenProcessor $token_processor
   *   Token processor.
   * @param \Drupal\ldap_user\FieldProvider $field_provider
   *   Field Provider.
   * @param \Drupal\Core\File\FileSystem $file_system
   *   File system.
   */
  public function __construct(
    ConfigFactory $config_factory,
    LoggerChannelInterface $logger,
    LdapDetailLog $detail_log,
    EntityTypeManagerInterface $entity_type_manager,
    ModuleHandlerInterface $module_handler,
    LdapUserManager $ldap_user_manager,
    TokenProcessor $token_processor,
    FieldProvider $field_provider,
    FileSystem $file_system) {
    $this->config = $config_factory->get('ldap_user.settings');
    $this->logger = $logger;
    $this->detailLog = $detail_log;
    $this->entityTypeManager = $entity_type_manager;
    $this->moduleHandler = $module_handler;
    $this->ldapUserManager = $ldap_user_manager;
    $this->tokenProcessor = $token_processor;
    $this->fieldProvider = $field_provider;
    $this->fileSystem = $file_system;
  }

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
      $this->loadServer();
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
      if (in_array(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE, $this->config->get('ldapEntryProvisionTriggers'))) {
        $this->loadServer();
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
      if (in_array(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE, $this->config->get('ldapEntryProvisionTriggers'))) {
        $this->loadServer();
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
   * Is provisioning of LDAP entries from Drupal users configured.
   *
   * @return bool
   *   Provisioning available.
   */
  private function provisionLdapEntriesFromDrupalUsers() {
    if ($this->config->get('ldapEntryProvisionServer') &&
      count(array_filter(array_values($this->config->get('ldapEntryProvisionTriggers')))) > 0) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Populate LDAP entry array for provisioning.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal account.
   * @param \Drupal\ldap_servers\Entity\Server $ldap_server
   *   LDAP server.
   * @param string $prov_event
   *   Provisioning event.
   *
   * @return \Symfony\Component\Ldap\Entry
   *   Entry to send *to* LDAP.
   *
   * @throws \Drupal\ldap_user\Exception\LdapBadParamsException
   */
  private function buildLdapEntry(UserInterface $account, $prov_event) {
    $dn = '';
    $attributes = [];

    if (!is_object($account) || !is_object($this->ldapServer)) {
      throw new LdapBadParamsException('Missing user or server.');
    }

    $this->fieldProvider->loadAttributes(self::PROVISION_TO_LDAP, $this->ldapServer);

    $mappings = $this->fieldProvider->getAttributesSyncedOnEvent($prov_event);

    foreach ($mappings as $field_key => $field_detail) {

      // TODO: Trimming here shows that we should not be saving the brackets to
      // the database.
      $ldap_attribute_name = trim($field_detail->getLdapAttribute(), '[]');

      $attribute = $field_detail->getDrupalAttribute() == 'user_tokens' ? $field_detail->getUserTokens() : $field_detail->getDrupalAttribute();
      $value = $this->fetchDrupalAttributeValue($account, $attribute, $ldap_attribute_name);

      if ($value) {
        if ($ldap_attribute_name == 'dn') {
          $dn = $value;
        }
        else {
          $attributes[$ldap_attribute_name][] = $value;
        }
      }
    }

    $entry = new Entry($dn, $attributes);

    // Allow other modules to alter $ldap_user.
    $params = [
      'prov_events' => $prov_event,
      'direction' => self::PROVISION_TO_LDAP,
    ];
    $this->moduleHandler
      ->alter('ldap_entry', $ldap_user_entry, $params);

    return $entry;
  }

  /**
   * Tokenize a user account.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user account.
   * @param array $attributes
   *   Keys for tokens:
   *     'all' signifies return
   *     all token/value pairs available; otherwise array lists
   *     token keys (e.g. property.name ...NOT [property.name])
   *
   * @return array
   *   Should return token/value pairs in array such as 'status' => 1,
   *   'uid' => 17.
   */
  private function fetchDrupalAttributes(UserInterface $account, array $attributes = []) {
    $tokens = [];
    foreach ($attributes as $attribute) {
      $tokens = array_merge($tokens, $this->fetchDrupalAccountAttribute($account, $attribute));
    }
    return $tokens;
  }

  /**
   * Fetch a single token.
   *
   * @param \Drupal\user\UserInterface $account
   *   LDAP entry.
   * @param string $token
   *   Token key.
   *
   * @return array
   *   Tokens.
   */
  private function fetchDrupalAccountAttribute(UserInterface $account, $token) {
    // Trailing period to allow for empty value.
    list($attribute_type, $attribute_name, $attribute_conversion) = explode('.', $token . '.');
    $value = FALSE;
    $tokens = [];

    switch ($attribute_type) {
      case 'field':
      case 'property':
        $value = $this->fetchDrupalAccountField($account, $attribute_name);
        break;

      case 'password':
        $value = $this->fetchDrupalAccountPassword($attribute_name);
        if (empty($value)) {
          // Do not evaluate empty passwords, to avoid overwriting them.
          return [NULL, NULL];
        }
        break;
    }

    if ($attribute_conversion == 'to-md5') {
      $value = md5($value);
    }
    elseif ($attribute_conversion == 'to-lowercase') {
      $value = mb_strtolower($value);
    }

    $tokens[sprintf('[%s]', $token)] = $value;

    return $tokens;
  }


  /**
   * Fetch regular field token.
   *
   * @param \Drupal\user\UserInterface $account
   *   User.
   * @param string $attribute_name
   *   Field name.
   *
   * @return string
   *   Field data.
   */
  private function fetchDrupalAccountField(UserInterface $account, $attribute_name) {
    $value = '';
    if (is_scalar($account->get($attribute_name)->value)) {
      $value = $account->get($attribute_name)->value;
    }
    elseif (!empty($account->get($attribute_name)->getValue())) {
      $file_reference = $account->get($attribute_name)->getValue();
      if (isset($file_reference[0]['target_id'])) {
        /** @var \Drupal\file\Entity\File $file */
        $file = $this->entityTypeManager
          ->getStorage('file')
          ->load($file_reference[0]['target_id']);
        if ($file) {
          $value = file_get_contents($this->fileSystem->realpath($file->getFileUri()));
        }
      }
    }
    return $value;
  }

  /**
   * Fetch the password token.
   *
   * @param string $attribute_name
   *   Field variant.
   *
   * @return string
   *   Password.
   */
  private function fetchDrupalAccountPassword($attribute_name) {
    $value = '';
    switch ($attribute_name) {

      case 'user':
      case 'user-only':
        $value = CredentialsStorage::getPassword();
        break;

      case 'user-random':
        $pwd = CredentialsStorage::getPassword();
        $value = ($pwd) ? $pwd : user_password();
        break;

      case 'random':
        $value = user_password();
        break;

    }
    return $value;
  }

  /**
   * Replace a single token.
   *
   * @param \Drupal\user\UserInterface $user
   *   The resource to act upon.
   * @param string $text
   *   The text such as "[dn]", "[cn]@my.org", "[displayName] [sn]",
   *   "Drupal Provisioned".
   *
   * @return string|null
   */
  private function fetchDrupalAttributeValue(UserInterface $user, string $text, string $type) {
    // Desired tokens are of form "cn","mail", etc.
    $desired_tokens = ConversionHelper::findTokensNeededForTemplate($text);

    if (empty($desired_tokens)) {
      // If no tokens exist in text, return text itself.
      return $text;
    }

    $tokens = $this->fetchDrupalAttributes($user, $desired_tokens);

    // This is inelegant but otherwise we cannot support compound tokens for DN.
    if ($type == 'dn') {
      foreach ($tokens as $key => $value) {
        $tokens[$key] = $this->ldapEscapeDn($value);
      }
    }

    // TODO: Not a great solution.
    // We are adding those lowercase duplicates to make sure we can
    // replace all placeholders independent of their case. Note that as a
    // workaround we are lowercasing those on form saving for now.

    foreach ($tokens as $attribute => $value) {
      $tokens[mb_strtolower($attribute)] = $value;
    }

    $attributes = array_keys($tokens);
    $values = array_values($tokens);
    $result = str_replace($attributes, $values, $text);

    // Strip out any un-replaced tokens.
    $result = preg_replace('/^\[.*\]$/', '', $result);

    if ($result == '') {
      $result = NULL;
    }
    return $result;
  }

  /**
   * Load provisioning server from database.
   */
  private function loadServer() {
    $this->ldapServer = $this->entityTypeManager
      ->getStorage('ldap_server')
      ->load($this->config->get('ldapEntryProvisionServer'));
    $this->ldapUserManager->setServer($this->ldapServer);
  }

  /**
   * Provision an LDAP entry if none exists.
   *
   * If one exists do nothing, takes Drupal user as argument.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal user.
   *
   * @return bool
   *   Provisioning successful.
   */
  private function provisionLdapEntry(UserInterface $account) {

    if ($account->isAnonymous()) {
      $this->logger->notice('Cannot provision LDAP user unless corresponding Drupal account exists.');
      return FALSE;
    }

    if (!$this->config->get('ldapEntryProvisionServer')) {
      $this->logger->error('No provisioning server enabled');
      return FALSE;
    }

    try {
      $entry = $this->buildLdapEntry($account, self::EVENT_CREATE_LDAP_ENTRY);
    } catch (\Exception $e) {
      $this->logger->error('User or server is missing during LDAP provisioning: %message', [
        '%message',
        $e->getMessage(),
      ]);
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
    $this->moduleHandler->alter('ldap_entry_pre_provision', $entry, $this->ldapServer, $context);
    if ($this->ldapUserManager->createLdapEntry($entry)) {
      $callback_params = [$entry, $this->ldapServer, $context];
      $this->moduleHandler->invokeAll('ldap_entry_post_provision', $callback_params);
      $this->updateUserProvisioningReferences($account, $entry);

    }
    else {
      $this->logger->error('LDAP entry for @username cannot be created on @sid not created because of an error. Proposed DN: %dn)',
        [
          '%dn' => $entry->getDn(),
          '@sid' => $this->ldapServer->id(),
          '@username' => @$account->getAccountName(),
        ]);
      return FALSE;
    }

    $this->detailLog->log(
      'LDAP entry for @username on server @sid created for DN %dn.',
      [
        '%dn' => $entry->getDn(),
        '@sid' => $this->ldapServer->id(),
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
   * @param \Symfony\Component\Ldap\Entry $entry
   *
   * @throws \Drupal\Core\Entity\EntityStorageException
   */
  private function updateUserProvisioningReferences(
    UserInterface $account,
    Entry $entry
  ) {
    $ldap_user_prov_entry = $this->ldapServer->id() . '|' . $entry->getDn();
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

    try {
      $entry = $this->buildLdapEntry($account, self::EVENT_SYNC_TO_LDAP_ENTRY);
    } catch (\Exception $e) {
      $this->logger->error('Unable to prepare LDAP entry: %message', [
        '%message',
        $e->getMessage(),
      ]);
      return;
    }

    if (!empty($entry->getDn())) {
      // Stick $proposedLdapEntry in $ldap_entries array for drupal_alter.
      $context = [
        'action' => 'update',
        'corresponding_drupal_data_type' => 'user',
        'account' => $account,
      ];
      $this->moduleHandler->alter('ldap_entry_pre_provision', $entry, $this->ldapServer, $context);
      $this->ldapUserManager->modifyLdapEntry($entry);
      $params = [$entry, $this->ldapServer, $context];
      $this->moduleHandler->invokeAll('ldap_entry_post_provision', $params);
      $tokens = [
        '%dn' => $entry->getDn(),
        '%sid' => $this->ldapServer->id(),
        '%username' => $account->getAccountName(),
        '%uid' => (!method_exists($account, 'id') || empty($account->id())) ? '' : $account->id(),
      ];
      $this->logger->info('LDAP entry on server %sid synced dn=%dn for username=%username, uid=%uid', $tokens);
    }
  }

  /**
   *
   *
   * @param \Drupal\user\UserInterface $account
   *
   * @return bool|\Symfony\Component\Ldap\Entry|null
   */
  private function checkExistingLdapEntry(UserInterface $account) {
    $authmap = \Drupal::service('externalauth.authmap')
      ->get($account->id(), 'ldap_user');
    if ($authmap) {
      return $this->ldapUserManager->queryAllBaseDnLdapForUsername($authmap);
    }
    return FALSE;
  }

}
