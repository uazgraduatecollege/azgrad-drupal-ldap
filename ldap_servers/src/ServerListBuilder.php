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
    $header['type'] = $this->t('Type');
    $header['status'] = $this->t('Enabled');
    $header['address'] = $this->t('Server address');
    $header['current_status'] = $this->t('Server reachable');
    return $header + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity) {
    $row = [];
    $row['label'] = $this->getLabel($entity);
    $row['type'] = $entity->get('type');
    $row['status'] = $entity->get('status') ? 'Yes' : 'No';
    $row['address'] = $entity->get('address');
    $row['current_status'] = $this->checkStatus($entity->id());
    return $row + parent::buildRow($entity);
  }

  /**
   * Format a server status response.
   *
   * @param string $server_id
   *   Server ID.
   *
   * @return \Drupal\Core\StringTranslation\TranslatableMarkup
   *   The status string.
   */
  private function checkStatus($server_id) {
    $server = Server::load($server_id);
    $connection_result = $server->connect();
    if ($server->get('status')) {
      if ($connection_result == Server::LDAP_SUCCESS) {
        if ($server->get('bind_method') == 'anon' || $server->get('bind_method') == 'anon_user') {
          $bind_result = $server->bind(NULL, NULL, TRUE);
        }
        else {
          $bind_result = $server->bind();
        }
        if ($bind_result == Server::LDAP_SUCCESS) {
          return t('Server available');
        }
        else {
          return t('Connection successful, bind failed.');
        }
      }
      else {
        return t('Cannot connect');
      }
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
