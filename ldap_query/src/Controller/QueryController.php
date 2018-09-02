<?php

namespace Drupal\ldap_query\Controller;

use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\ldap_servers\LdapBridge;
use Symfony\Component\Ldap\Exception\LdapException;

/**
 * Controller class for LDAP queries, in assistance to the entity itself.
 */
class QueryController {

  /**
   * @var \Symfony\Component\Ldap\Entry[]
   */
  private $results = [];
  private $qid;
  private $query;

  protected $storage;
  protected $ldapBridge;
  protected $logger;

  /**
   * Constructor.
   */
  public function __construct(EntityTypeManager $entity_type_manager, LdapBridge $ldap_bridge, LoggerChannelInterface $logger) {
    $this->storage = $entity_type_manager->getStorage('ldap_query_entity');
    $this->ldapBridge = $ldap_bridge;
    $this->logger = $logger;
  }

  /**
   *
   */
  public function load($id) {
    $this->qid = $id;
    $this->query = $this->storage->load($this->qid);
  }

  /**
   * Returns the filter.
   *
   * @return string
   *   Set filter.
   */
  public function getFilter() {
    return $this->query->get('filter');
  }

  /**
   * Execute query.
   *
   * @param null|string $filter
   *   Optional parameter to override filters. Useful for Views and other
   *   queries requiring filtering.
   */
  public function execute($filter = NULL) {
    if ($this->query) {
      if ($filter == NULL) {
        $filter = $this->query->get('filter');
      }

      // TODO: exception handling.
      $this->ldapBridge->setServerById($this->query->get('server_id'));

      if ($this->ldapBridge->bind()) {

        foreach ($this->query->getProcessedBaseDns() as $base_dn) {
          $options = [
            'filter' => $this->query->getProcessedAttributes(),
            'maxItems' => $this->query->get('size_limit'),
            'timeout' => $this->query->get('time_limit'),
            'deref' => $this->query->get('dereference'),
            'scope' => $this->query->get('scope'),
          ];

          try {
            $ldap_response = $this->ldapBridge
              ->get()
              ->query($base_dn, $filter, $options)
              ->execute()
              ->toArray();
          }
          catch (LdapException $e) {
            $this->logger->warning('LDAP query exception %message', ['@message' => $e->getMessage()]);
            $ldap_response = FALSE;
          }

          if ($ldap_response && !empty($ldap_response)) {
            $this->results = array_merge($this->results, $ldap_response);
          }
        }
      }
    }
    else {
      $this->logger->warning('Could not load query @query', ['@query' => $this->qid]);
    }
  }

  /**
   * Return raw results.
   *
   * @return \Symfony\Component\Ldap\Entry[]
   *   Raw results.
   */
  public function getRawResults() {
    return $this->results;
  }

  /**
   * Return available fields.
   *
   * @return array
   *   Available fields.
   */
  public function availableFields() {
    $attributes = [];
    // We loop through all results since some users might not have fields set
    // for them and those are missing and not null.
    foreach ($this->results as $result) {
      foreach ($result->getAttributes() as $field_name => $field_value) {
        $attributes[$field_name] = $field_name;
      }
    }
    return $attributes;
  }

}
