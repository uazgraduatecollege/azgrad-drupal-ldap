<?php

namespace Drupal\ldap_query\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\FormBase;
use Drupal\ldap_query\Controller\QueryController;
use Drupal\ldap_servers\Form\ServerTestForm;

/**
 * Test form for queries.
 */
class QueryTestForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_query_test_form';
  }

  /**
   * {@inheritdoc}
   */
  public function __construct() {

  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, $ldap_query_entity = NULL) {
    if ($ldap_query_entity) {
      // FIXME: DI.
      $controller = new QueryController($ldap_query_entity);
      $controller->execute();
      $data = $controller->getRawResults();

      $form['result_count'] = [
        '#markup' => '<h2>' . $this->t('@count results', ['@count' => count($data)]) . '</h2>',
      ];

      $header[] = 'DN';
      $attributes = $controller->availableFields();
      foreach ($attributes as $attribute) {
        $header[] = $attribute;
      }

      $rows = [];
      foreach ($data as $entry) {
        $row = [$entry->getDn()];
        foreach ($attributes as $attribute_data) {
          if (!$entry->hasAttribute($attribute_data)) {
            $row[] = 'No data';
          }
          else {
            if (count($entry->getAttribute($attribute_data)) > 1) {
              $row[] = ServerTestForm::binaryCheck(implode("\n", $entry->getAttribute($attribute_data)));
            }
            else {
              $row[] = ServerTestForm::binaryCheck($entry->getAttribute($attribute_data)[0]);
            }
          }
        }
        $rows[] = $row;
      }

      $form['result'] = [
        '#type' => 'table',
        '#header' => $header,
        '#rows' => $rows,
      ];
      return $form;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {

  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

  }

}
