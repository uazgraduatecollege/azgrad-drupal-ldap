<?php

namespace Drupal\ldap_user\Form;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_user\FieldProvider;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Provides the form to configure user configuration and field mapping.
 */
abstract class LdapUserBaseForm extends ConfigFormBase implements LdapUserAttributesInterface, ContainerInjectionInterface {

  protected $moduleHandler;

  protected $entityTypeManager;

  protected $fieldProvider;

  protected $drupalAcctProvisionServerOptions;

  protected $ldapEntryProvisionServerOptions;

  protected $currentConfig;

  /**
   * {@inheritdoc}
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    ModuleHandler $module_handler,
    EntityTypeManagerInterface $entity_type_manager,
    FieldProvider $field_provider) {
    parent::__construct($config_factory);
    $this->moduleHandler = $module_handler;
    $this->entityTypeManager = $entity_type_manager;
    $this->fieldProvider = $field_provider;

    $this->prepareBaseData();
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('module_handler'),
      $container->get('entity_type.manager'),
      $container->get('ldap_user.field_provider')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getEditableConfigNames() {
    return ['ldap_user.settings'];
  }

  /**
   * Load servers and set their default values.
   *
   * TODO: Duplicated in LdapUserAdminForm.
   */
  protected function prepareBaseData() {
    $storage = $this->entityTypeManager->getStorage('ldap_server');
    $ids = $storage
      ->getQuery()
      ->condition('status', 1)
      ->execute();
    foreach ($storage->loadMultiple($ids) as $sid => $server) {
      /** @var \Drupal\ldap_servers\Entity\Server $server */
      $enabled = ($server->get('status')) ? 'Enabled' : 'Disabled';
      $this->drupalAcctProvisionServerOptions[$sid] = $server->label() . ' (' . $server->get('address') . ') Status: ' . $enabled;
      $this->ldapEntryProvisionServerOptions[$sid] = $server->label() . ' (' . $server->get('address') . ') Status: ' . $enabled;
    }

    $this->drupalAcctProvisionServerOptions['none'] = $this->t('None');
    $this->ldapEntryProvisionServerOptions['none'] = $this->t('None');
    $this->currentConfig = $this->config('ldap_user.settings');
  }

}
