<?php

namespace Drupal\ldap_query\Plugin\views\field;

use Drupal\Core\Form\FormStateInterface;
use Drupal\views\Plugin\views\field\FieldPluginBase;
use Drupal\views\ResultRow;

/**
 * The handler for loading a specific LDAP field.
 *
 * @ingroup views_field_handlers
 *
 * @ViewsField("ldap_attribute")
 */
class LdapAttribute extends FieldPluginBase {

  /**
   *
   */
  public function render(ResultRow $values) {
    // TODO: Check plain
    if ($this->getValue($values)) {
      return $this->getValue($values);
    }
  }

  /**
   *

  public function element_type($none_supported = FALSE, $default_empty = FALSE, $inline = FALSE) {
    if (isset($this->definition['element type'])) {
      return $this->definition['element type'];
    }

    return 'div';
  }
*/
  /**
   *

  public function option_definition() {
    $options                    = parent::option_definition();
    $options['multivalue']      = ['default' => 'v-all'];
    $options['value_separator'] = ['default' => ''];
    $options['index_value']     = ['default' => 0];
    return $options;
  }*/

  /**
   * Add the field for the LDAP Attribute.

  public function options_form(&$form, &$form_state) {
    parent::options_form($form, $form_state);
    $form['multivalue'] = [
    // It should be 'radios', but it makes #dependency not to work.
      '#type' => 'select',
      '#title' => t('Values to show'),
      '#description' => t('What to do with multi-value attributes'),
      '#options' => [
        'v-all' => t('All values'),
        'v-index' => t('Show Nth value'),
        'v-count' => t('Count values'),
      ],
      '#default_value' => $this->options['multivalue'],
      '#required' => TRUE,
    ];
    $form['value_separator'] = [
      '#type' => 'textfield',
      '#title' => t('Value separator'),
      '#description' => t('Separator to use between values in multivalued attributes'),
      '#default_value' => $this->options['value_separator'],
      '#dependency' => [
        'edit-options-multivalue' => ['v-all'],
      ],
    ];
    $form['index_value'] = [
      '#type' => 'textfield',
      '#title' => t('Index'),
      '#description' => t('Index of the value to show. Use negative numbers to index from last item (0=First, -1=Last)'),
      '#default_value' => $this->options['index_value'],
      '#dependency' => [
        'edit-options-multivalue' => ['v-index'],
      ],
    ];
  }*/

  /**
   * {@inheritdoc}
   */
  public function usesGroupBy() {
    return FALSE;
  }



  /**
   * {@inheritdoc}
   */
  protected function defineOptions() {
    $options = parent::defineOptions();

    $options['hide_alter_empty'] = ['default' => FALSE];
    return $options;
  }

  /**
   * {@inheritdoc}
   */
  public function buildOptionsForm(&$form, FormStateInterface $form_state) {
    parent::buildOptionsForm($form, $form_state);
  }

}
