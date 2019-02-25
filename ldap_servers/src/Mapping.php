<?php

namespace Drupal\ldap_servers;

/**
 * Interface for the synchronization mappings ldap_user provides.
 */
class Mapping {

  private $id;
  private $label;
  private $configurable = FALSE;
  private $binary = FALSE;
  private $notes;
  private $enabled = FALSE;
  private $provisioningEvents = [];
  private $configurationModule;
  private $provisioningModule;
  private $ldapAttribute = '';
  private $drupalAttribute = '';
  private $userTokens = '';

  /**
   * Mapping constructor.
   *
   * @param string $id
   *   ID.
   * @param string $label
   *   Label.
   * @param bool $configurable
   *   Configurable.
   * @param bool $enabled
   *   Enabled.
   * @param array $provisioning_events
   *   Provisioning events.
   * @param string $configuration_module
   *   Configuration module.
   * @param string $provisioning_module
   *   Provisioning module.
   */
  public function __construct(
    string $id,
    string $label = '',
    bool $configurable = FALSE,
    bool $enabled = FALSE,
    array $provisioning_events = [],
    string $configuration_module = '',
    string $provisioning_module = '') {
    $this->id = $id;
    $this->label = $label;
    $this->configurable = $configurable;
    $this->enabled = $enabled;
    $this->provisioningEvents = $provisioning_events;
    $this->configurationModule = $configuration_module;
    $this->provisioningModule = $provisioning_module;
  }

  /**
   *
   */
  public function serialize() {
    return [
      'ldap_attr' => $this->getLdapAttribute(),
      'user_attr' => $this->getDrupalAttribute(),
      'convert' => $this->isBinary(),
      'user_tokens' => $this->getUserTokens(),
      'config_module' => $this->getConfigurationModule(),
      'prov_module' => $this->getProvisioningModule(),
      'prov_events' => $this->getProvisioningEvents(),
    ];
  }

  /**
   * Get label.
   *
   * @return null|string
   *   Label.
   */
  public function getLabel() {
    return $this->label;
  }

  /**
   * Set label.
   *
   * @param string $label
   *   Label.
   */
  public function setLabel($label) {
    $this->label = $label;
  }

  /**
   * Is configurable.
   *
   * @return bool
   *   Configurable.
   */
  public function isConfigurable() {
    return $this->configurable;
  }

  /**
   * Get notes.
   *
   * @return null|string
   *   Notes.
   */
  public function getNotes() {
    return $this->notes;
  }

  /**
   * Set Notes.
   *
   * @param string $notes
   *   Notes.
   */
  public function setNotes($notes) {
    $this->notes = $notes;
  }

  /**
   * Is enabled.
   *
   * @return bool
   *   Enabled.
   */
  public function isEnabled() {
    return $this->enabled;
  }

  /**
   * Set enabled.
   *
   * @param bool $enabled
   *   Enabled.
   */
  public function setEnabled(bool $enabled) {
    $this->enabled = $enabled;
  }

  /**
   * Get provisioning events.
   *
   * @return array
   *   Events.
   */
  public function getProvisioningEvents(): array {
    return $this->provisioningEvents;
  }

  /**
   * Provisioning event available?
   *
   * @param $event
   *   Event.
   *
   * @return bool
   *   Available.
   */
  public function hasProvisioningEvent($event) {
    if (in_array($event, $this->provisioningEvents)) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Set provisioning events.
   *
   * @param array $events
   *   Provisioning vents.
   */
  public function setProvisioningEvents(array $events) {
    $this->provisioningEvents = $events;
  }

  /**
   * @return null
   */
  public function getConfigurationModule() {
    return $this->configurationModule;
  }

  /**
   * @param null $configurationModule
   */
  public function setConfigurationModule($configurationModule) {
    $this->configurationModule = $configurationModule;
  }

  /**
   * @return null
   */
  public function getProvisioningModule() {
    return $this->provisioningModule;
  }

  /**
   * @param null $provisioningModule
   */
  public function setProvisioningModule($provisioningModule) {
    $this->provisioningModule = $provisioningModule;
  }

  /**
   * @return string
   */
  public function getLdapAttribute() {
    return $this->ldapAttribute;
  }

  /**
   * @param string $ldapAttribute
   */
  public function setLdapAttribute($ldapAttribute) {
    $this->ldapAttribute = $ldapAttribute;
  }

  /**
   * @return string
   */
  public function getDrupalAttribute() {
    return $this->drupalAttribute;
  }

  /**
   * @param string $drupalAttribute
   */
  public function setDrupalAttribute($drupalAttribute) {
    $this->drupalAttribute = $drupalAttribute;
  }

  /**
   * @return mixed
   */
  public function getId() {
    return $this->id;
  }

  /**
   * @return null
   */
  public function getUserTokens() {
    return $this->userTokens;
  }

  /**
   * @param null $userTokens
   */
  public function setUserTokens($userTokens) {
    $this->userTokens = $userTokens;
  }

  /**
   * @return bool
   */
  public function isBinary() {
    return $this->binary;
  }

  /**
   * @param bool $binary
   */
  public function convertBinary(bool $binary) {
    $this->binary = $binary;
  }

  /**
   * @param bool $configurable
   */
  public function setConfigurable(bool $configurable) {
    $this->configurable = $configurable;
  }

}
