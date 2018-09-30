<?php

namespace Drupal\ldap_servers;

class Mapping  {

  private $id;
  private $label;
  private $configurableToDrupal;
  private $configurableToLdap;
  private $source;
  private $notes;
  private $direction;
  private $enabled;
  private $provisioningEvents;
  private $configurationModule;
  private $provisioningModule;
  private $ldapAttribute;
  private $drupalAttribute;

  /**
   * Mapping constructor.
   *
   * @param $id
   * @param null $label
   * @param bool $configurable_to_drupal
   * @param bool $configurable_to_Ldap
   * @param null $source
   * @param null $notes
   * @param string $direction
   * @param bool $enabled
   * @param null $provisioning_events
   * @param null $configuration_module
   * @param null $provisioning_module
   * @param null $ldap_attribute
   * @param null $drupal_attribute
   */
  public function __construct(
    $id,
    $label = NULL,
    $configurable_to_drupal = FALSE,
    $configurable_to_Ldap = FALSE,
    $source = NULL,
    $notes = NULL,
    $direction = LdapUserAttributesInterface::PROVISION_TO_ALL,
    $enabled = FALSE,
    $provisioning_events = NULL,
    $configuration_module = NULL,
    $provisioning_module = NULL,
    $ldap_attribute = NULL,
    $drupal_attribute = NULL) {
    $this->id = $id;
    $this->label = $label;
    $this->configurableToDrupal = $configurable_to_drupal;
    $this->configurableToLdap = $configurable_to_Ldap;
    $this->source = $source;
    $this->notes = $notes;
    $this->direction = $direction;
    $this->enabled = $enabled;
    $this->provisioningEvents = $provisioning_events;
    $this->configurationModule = $configuration_module;
    $this->provisioningModule = $provisioning_module;
    $this->ldapAttribute = $ldap_attribute;
    $this->drupalAttribute = $drupal_attribute;

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
   * @return bool
   */
  public function isConfigurableToEither() {
    return ($this->configurableToLdap || $this->configurableToDrupal) ? TRUE : FALSE;
  }

  /**
   * @return bool
   */
  public function isConfigurableToDrupal() {
    return $this->configurableToDrupal;
  }

  /**
   * @param bool $configurableToDrupal
   */
  public function setConfigurableToDrupal(bool $configurableToDrupal) {
    $this->configurableToDrupal = $configurableToDrupal;
  }

  /**
   * @return bool
   */
  public function isConfigurableToLdap() {
    return $this->configurableToLdap;
  }

  /**
   * @param bool $configurableToLdap
   */
  public function setConfigurableToLdap(bool $configurableToLdap) {
    $this->configurableToLdap = $configurableToLdap;
  }

  /**
   * @return null
   */
  public function getSource() {
    return $this->source;
  }

  /**
   * @param null $source
   */
  public function setSource($source) {
    $this->source = $source;
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
   * @return null
   */
  public function getDirection() {
    return $this->direction;
  }

  /**
   * @param null $direction
   */
  public function setDirection($direction) {
    $this->direction = $direction;
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
  public function getProvEvents() {
    return $this->prov_events;
  }

  /**
   * @param array $prov_events
   */
  public function setProvEvents(array $prov_events) {
    $this->prov_events = $prov_events;
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
   * @return mixed
   */
  public function getProvisioningEvents() {
    return $this->provisioning_events;
  }

  /**
   * @param mixed $provisioning_events
   */
  public function setProvisioningEvents($provisioning_events) {
    $this->provisioning_events = $provisioning_events;
  }

}
