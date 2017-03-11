<?php

namespace Drupal\ldap_query\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\FormBase;
use Drupal\ldap_query\Controller\QueryController;
use Drupal\ldap_servers\Form\ServerTestForm;
use Drupal\ldap_servers\Helper\MassageAttributes;

/**
 *
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
      $controller = new QueryController();
      $data = $controller->query($ldap_query_entity);

      $form['result_count'] = [
        '#markup' => '<h2>' . t('@count results', array('@count' => $data['count'])) . '</h2>',
      ];
      unset($data['count']);

      $header[] = 'DN';

      $attributes = [];
      // Use the first result to determine available attributes.
      if (isset($data[0]) && $data[0]) {
        foreach ($data[0] as $k => $v) {
          if (is_numeric($k)) {
            $attributes[] = $v;
          }
        }
      }

      foreach ($attributes as $attribute) {
        $header[] = $attribute;
      }

      $rows = [];

      foreach ($data as $i => $entry) {
        $row = [$entry['dn']];
        foreach ($attributes as $j => $attribute_data) {
          $massager = new MassageAttributes();
          $processedAttributeName = $massager->processAttributeName($attribute_data);
          if (!isset($entry[$processedAttributeName])) {
            $row[] = 'No data';
          }
          elseif (is_array($entry[$processedAttributeName])) {
            unset($entry[$processedAttributeName]['count']);
            $row[] = ServerTestForm::binaryCheck(join("\n", $entry[$processedAttributeName]));
          }
          else {
            $row[] = ServerTestForm::binaryCheck($entry[$processedAttributeName]);
          }
        }
        unset($entry['count']);
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
   *
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {

  }

  /**
   *
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {


  }

}
