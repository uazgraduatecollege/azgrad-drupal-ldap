<?php

namespace Drupal\ldap_query\Plugin\views\query;

use Drupal\Component\Utility\SafeMarkup;
use Drupal\Component\Utility\Unicode;
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
  public $where = [];

  /**
   * Collection of sort criteria.
   *
   * @var array
   */
  public $orderby = [];

  /**
   * {@inheritdoc}
   */
  public function build(ViewExecutable $view) {
    // Store the view in the object to be able to use it later.
    $this->view = $view;

    $view->initPager();

    // Let the pager modify the query to add limits.
    $view->pager->query();

    $view->build_info['query'] = $this->query();
    $view->build_info['count_query'] = $this->query(TRUE);
  }

  /**
   * Execute the query.
   *
   * @param \Drupal\views\ViewExecutable $view
   *   The view.
   *
   * @return bool|void
   *   Nothing if query can be executed.
   */
  public function execute(ViewExecutable $view) {
    if (!isset($this->options['query_id']) || empty($this->options['query_id'])) {
      \Drupal::logger('ldap')->error('You are trying to use Views without having chosen an LDAP Query under Advanced => Query settings.');
      return FALSE;
    }
    $start = microtime(TRUE);

    $controller = new QueryController($this->options['query_id']);
    $filter = $this->buildLdapFilter($controller->getFilter());

    $controller->execute($filter);
    $results = $controller->getRawResults();
    $fields = $controller->availableFields();

    $index = 0;
    unset($results['count']);
    $rows = [];
    foreach ($results as $result) {
      $row = [];
      // TODO: Try to only fetch requested fields instead of all available.
      foreach ($fields as $field_key => $void) {
        if (isset($result[$field_key])) {
          unset($result[$field_key]['count']);
          $row[$field_key] = $result[$field_key];
        }
      }
      $row['index'] = $index++;
      $rows[] = $row;
    }

    if (!empty($this->orderby) && !empty($rows)) {
      $rows = $this->sortResults($rows);
    }

    foreach ($rows as $row) {
      $view->result[] = new ResultRow($row);
    }

    // Pager.
    // Paging in the query is not possible since filters and sorting affect it.
    $totalItems = count($view->result);
    $offset = ($view->pager->getCurrentPage() * $view->pager->getItemsPerPage());
    $currentLimit = ($view->pager->getCurrentPage() + 1) * $view->pager->getItemsPerPage();

    $view->result = array_splice($view->result, $offset, $currentLimit);
    $view->pager->postExecute($view->result);
    $view->pager->total_items = $totalItems;
    $view->pager->setOffset($offset);
    $view->pager->updatePageInfo();
    $view->total_rows = $view->pager->getTotalItems();
    // Timing information.
    $view->execute_time = microtime(TRUE) - $start;
  }

  /**
   * Sort the results.
   *
   * @param array $results
   *   Results to operate on.
   *
   * @return array
   *   Result data.
   */
  private function sortResults(array $results) {
    $parameters = [];
    $orders = $this->orderby;
    $set = [];
    foreach ($orders as $orderCriterion) {
      foreach ($results as $key => $row) {
        // TODO: Could be improved by making the element index configurable.
        $orderCriterion['data'][$key] = $row[$orderCriterion['field']][0];
        $set[$key][$orderCriterion['field']] = $row[$orderCriterion['field']][0];
        $set[$key]['index'] = $key;
      }
      $parameters[] = $orderCriterion['data'];
      if ($orderCriterion['direction'] == 'ASC') {
        $parameters[] = SORT_ASC;
      }
      else {
        $parameters[] = SORT_DESC;
      }
    }
    $parameters[] = &$set;
    call_user_func_array('array_multisort', $parameters);

    $processedResults = [];
    foreach ($set as $row) {
      $processedResults[] = $results[$row['index']];
    }

    return $processedResults;
  }

  /**
   * {@inheritdoc}
   */
  public function ensureTable($table, $relationship = NULL) {
    return '';
  }

  /**
   * {@inheritdoc}
   */
  public function addField($table, $field, $alias = '', $params = []) {
    return $field;
  }

  /**
   * {@inheritdoc}
   */
  public function addOrderBy($table, $field, $order, $alias = '', $params = []) {
    $this->orderby[] = [
      'field' => $field,
      'direction' => $order,
    ];
  }

  /**
   * {@inheritdoc}
   */
  protected function defineOptions() {
    $options = parent::defineOptions();
    $options['query_id'] = [
      'default' => NULL,
    ];
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
      '#description' => $this->t('The LDAP query you want Views to use.'),
      '#required' => TRUE,
    ];
  }

  /**
   * {@inheritdoc}
   */
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
    if (!empty($operator) && $operator != 'LIKE') {
      $this->where[$group]['conditions'][] = [
        'field' => $field,
        'value' => $value,
        'operator' => $operator,
      ];
    }
  }

  /**
   * Compiles all conditions into a set of LDAP requirements.
   *
   * @return string
   *   Condition string.
   */
  public function buildConditions() {
    $operator = ['AND' => '&', 'OR' => '|'];
    $mainGroup = '';
    foreach ($this->where as $group => $info) {
      if (!empty($info['conditions'])) {
        $subGroup = '';
        foreach ($info['conditions'] as $key => $clause) {
          $item = '(' . $clause['field'] . '=' . SafeMarkup::checkPlain($clause['value']) . ')';
          if (Unicode::substr($clause['operator'], 0, 1) == '!') {
            $subGroup .= "(!$item)";
          }
          else {
            $subGroup .= $item;
          }
        }
        if (count($info['conditions']) <= 1) {
          $mainGroup .= $subGroup;
        }
        else {
          $mainGroup .= '(' . $operator[$info['type']] . $subGroup . ')';
        }
      }
    }

    if (count($this->where) <= 1) {
      $output = $mainGroup;
    }
    else {
      // TODO: Bug hidden here regarding multiple groups, which are not working
      // properly.
      $output = '(' . $operator[$this->group_operator] . $mainGroup . ')';
    }

    return $output;
  }

  /**
   * Collates Views arguments and filters for a modified query.
   *
   * @param string $standardFilter
   *   The filter in LDAP query which gets overwritten.
   *
   * @return string
   *   Combined string.
   */
  private function buildLdapFilter($standardFilter) {
    $searchFilter = $this->buildConditions();
    if (!empty($searchFilter)) {
      $finalFilter = '(&' . $standardFilter . $searchFilter . ')';
    }
    else {
      $finalFilter = $standardFilter;
    }
    return $finalFilter;
  }

}
