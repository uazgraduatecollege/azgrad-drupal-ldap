<?php

namespace Drupal\ldap_servers;

use Drupal\Core\Url;
use Drupal\Core\Config\Entity\ConfigEntityListBuilder;
use Drupal\Core\Entity\EntityInterface;
use Drupal\ldap_servers\Entity\Server;

/**
 * Provides a listing of Server entities.
 */
class ServerListBuilder extends ConfigEntityListBuilder {

  /**
   * {@inheritdoc}
   *
   * Building the header and content lines for the server list.
   *
   * Calling the parent::buildHeader() adds a column for the possible actions
   * and inserts the 'edit' and 'delete' links as defined for the entity type.
   */
  public function buildHeader() {
    $header['label'] = $this->t('Name');
    $header['bind_method'] = $this->t('Method');
    $header['binddn'] = $this->t('Account');
    $header['status'] = $this->t('Enabled');
    $header['address'] = $this->t('Server address');
    $header['port'] = $this->t('Server port');
    $header['current_status'] = $this->t('Server reachable');
    return $header + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity) {
    /** @var \Drupal\ldap_servers\Entity\Server $entity */
    $row = [];
    $row['label'] = $this->getLabel($entity);
    $row['bind_method'] = ucfirst($entity->getFormattedBind());
    if ($entity->get('bind_method') == 'service_account') {
      $row['binddn'] = $entity->get('binddn');
    }
    else {
      $row['binddn'] = $this->t('N/A');
    }
    $row['status'] = $entity->get('status') ? 'Yes' : 'No';
    $row['address'] = $entity->get('address');
    $row['port'] = $entity->get('port');
    $row['current_status'] = $this->checkStatus($entity);

    $fields = [
      'bind_method',
      'binddn',
      'status',
      'address',
      'port',
    ];

    foreach ($fields as $field) {
      if ($entity->get($field) != $entity->get($field)) {
        $row[$field] .= ' ' . $this->t('(overridden)');
      }
    }

    return $row + parent::buildRow($entity);
  }

  /**
   * Format a server status response.
   *
   * @param \Drupal\ldap_servers\Entity\Server $server
   *   Server.
   *
   * @return \Drupal\Core\StringTranslation\TranslatableMarkup
   *   The status string.
   */
  private function checkStatus(Server $server) {
    /** @var \Drupal\ldap_servers\LdapBridge $bridge */
    $bridge = \Drupal::service('ldap.bridge');
    $bridge->setServer($server);

    if ($server->get('status')) {
      if ($bridge->bind()) {
        return t('Server available');
      }
      else {
        return t('Binding issues, please see log.');
      }
    }
    else {
      return t('Deactivated');
    }
  }

  /**
   * Get Operations.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   Entity interface.
   *
   * @return array
   *   Available operations in dropdown.
   */
  public function getOperations(EntityInterface $entity) {
    $operations = parent::getDefaultOperations($entity);
    if (!isset($operations['test'])) {
      $operations['test'] = [
        'title' => $this->t('Test'),
        'weight' => 10,
        'url' => Url::fromRoute('entity.ldap_server.test_form', ['ldap_server' => $entity->id()]),
      ];
    }
    if ($entity->get('status') == 1) {
      $operations['disable'] = [
        'title' => $this->t('Disable'),
        'weight' => 15,
        'url' => Url::fromRoute('entity.ldap_server.enable_disable_form', ['ldap_server' => $entity->id()]),
      ];
    }
    else {
      $operations['enable'] = [
        'title' => $this->t('Enable'),
        'weight' => 15,
        'url' => Url::fromRoute('entity.ldap_server.enable_disable_form', ['ldap_server' => $entity->id()]),
      ];
    }
    return $operations;
  }

}
