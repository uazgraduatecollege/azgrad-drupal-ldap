<?php

namespace Drupal\ldap_query\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\FormBase;
use Drupal\ldap_query\Controller\QueryController;
use Drupal\ldap_query\Entity\QueryEntity;
use Drupal\ldap_servers\Form\ServerTestForm;
use Drupal\ldap_servers\MassageFunctions;
use Drupal\ldap_user\LdapUserConf;
use Drupal\user\Entity\User;
use PDO;

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
          $massager = new MassageFunctions();
          $processed_attribute_name = $massager->massage_text($attribute_data, 'attr_name', $massager::$query_array);
          if (!isset($entry[$processed_attribute_name])) {
            $row[] = 'No data';
          }
          elseif (is_array($entry[$processed_attribute_name])) {
            unset($entry[$processed_attribute_name]['count']);
            $row[] = ServerTestForm::binaryCheck(join("\n", $entry[$processed_attribute_name]));
          }
          else {
            $row[] = ServerTestForm::binaryCheck($entry[$processed_attribute_name]);
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
