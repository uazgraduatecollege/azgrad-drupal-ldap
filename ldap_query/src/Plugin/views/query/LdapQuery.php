<?php

namespace Drupal\ldap_query\Plugin\views\query;

use Drupal\Core\Form\FormStateInterface;
use Drupal\ldap_query\Controller\QueryController;
use Drupal\views\Plugin\views\query\QueryPluginBase;
use Drupal\views\ResultRow;
use Drupal\views\ViewExecutable;

/**
 * Views query plugin for an SQL query.
 *
 * @ingroup views_query_plugins
 *
 * @ViewsQuery(
 *   id = "ldap_query",
 *   title = @Translation("LDAP Query"),
 *   help = @Translation("Query will be generated and run via LDAP.")
 * )
 */
class LdapQuery extends QueryPluginBase {
  /**
   * Collection of filter criteria.
   *
   * @var array
   */
  protected $where;

  public function execute(ViewExecutable $view) {
    if (!isset($this->options['query_id']) || empty($this->options['query_id'])) {
      return FALSE;
    }
    $controller = new QueryController($this->options['query_id']);
    $controller->execute();
    $results = $controller->getRawResults();
    $fields = $controller->availableFields();

    $index = 0;
    unset($results['count']);
    foreach ($results as $result) {
      $row = [];
      foreach ($fields as $field_key => $void) {
        if (isset($result[$field_key])) {
          unset($result[$field_key]['count']);
          $row[$field_key] = $result[$field_key][0];
        }
      }
      $row['index'] = $index++;
      $view->result[] = new ResultRow($row);
    }

  }

  public function ensureTable($table, $relationship = NULL) {
    return '';
  }
  public function addField($table, $field, $alias = '', $params = array()) {
    return $field;
  }

  /**
   * {@inheritdoc}
   */
  protected function defineOptions() {
    $options = parent::defineOptions();
    $options['query_id'] = array(
      'default' => NULL,
    );
    return $options;
  }
  /**
   * {@inheritdoc}
   */
  public function buildOptionsForm(&$form, FormStateInterface $form_state) {
    parent::buildOptionsForm($form, $form_state);

    $qids = \Drupal::EntityQuery('ldap_query_entity')
      ->condition('status', 1)
      ->execute();

    $form['query_id'] = [
      '#type' => 'select',
      '#options' => $qids,
      '#title' => $this->t('Ldap Query'),
      '#default_value' => $this->options['query_id'],
      '#description' => $this->t('The Ldap query you want Views to use.'),
      '#required' => TRUE,
    ];
  }

  public function addWhere($group, $field, $value = NULL, $operator = NULL) {
    // Ensure all variants of 0 are actually 0. Thus '', 0 and NULL are all
    // the default group.
    if (empty($group)) {
      $group = 0;
    }
    // Check for a group.
    if (!isset($this->where[$group])) {
      $this->setWhereGroup('AND', $group);
    }
    $this->where[$group]['conditions'][] = [
      'field' => $field,
      'value' => $value,
      'operator' => $operator,
    ];
  }

  // TODO: Support Filter

  // TODO: Support sort

  // TODO: Support field formatter for photos.

}
