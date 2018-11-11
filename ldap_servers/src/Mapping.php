<?php

namespace Drupal\ldap_servers;

/**
 *
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
   * @param $id
   * @param null $label
   * @param bool $configurable
   * @param bool $enabled
   * @param null $provisioning_events
   * @param null $configuration_module
   * @param null $provisioning_module
   */
  public function __construct(
    $id,
    $label = NULL,
    $configurable = FALSE,
    $enabled = FALSE,
    $provisioning_events = [],
    $configuration_module = NULL,
    $provisioning_module = NULL) {
    $this->id = $id;
    $this->label = $label;
    $this->configurable = $configurable;
    $this->enabled = $enabled;
    $this->provisioningEvents = $provisioning_events;
    $this->configurationModule = $configuration_module;
    $this->provisioningModule = $provisioning_module;
  }

  /**
   * @return null|string
   */
  public function getLabel() {
    return $this->label;
  }

  /**
   * @param string $name
   */
  public function setLabel($label) {
    $this->label = $label;
  }

  /**
   *
   */
  public function isConfigurable() {
    return $this->configurable;
  }

  /**
   * @return null
   */
  public function getNotes() {
    return $this->notes;
  }

  /**
   * @param null $notes
   */
  public function setNotes($notes) {
    $this->notes = $notes;
  }

  /**
   * @return bool
   */
  public function isEnabled() {
    return $this->enabled;
  }

  /**
   * @param bool $enabled
   */
  public function setEnabled(bool $enabled) {
    $this->enabled = $enabled;
  }

  /**
   * @return array
   */
  public function getProvisioningEvents() {
    return $this->provisioningEvents;
  }

  /**
   * @param array $prov_events
   */
  public function setProvisioningEvents(array $prov_events) {
    $this->provisioningEvents = $prov_events;
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
