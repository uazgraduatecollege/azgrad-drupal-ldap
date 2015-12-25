<?php

/**
 * @file
 * Contains \Drupal\ldap_authorization\Plugin\authorization\provider\LDAPAuthorizationProvider.
 */

namespace Drupal\ldap_authorization\Plugin\authorization\provider;

use Drupal\Core\Form\FormStateInterface;

use Drupal\authorization\Provider\ProviderPluginBase;
/**
 * @AuthorizationProvider(
 *   id = "ldap_provider",
 *   label = @Translation("LDAP Authorization"),
 *   description = @Translation("LDAP provider to the Authorization API.")
 * )
 */
class LDAPAuthorizationProvider extends ProviderPluginBase {

  public $synchOnLogon = TRUE;
  public $providerType = 'ldap';
  public $allowConsumerObjectCreation = TRUE;

  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {

    $provider_tokens = array(
      '!profile_name' => '!profile_name',
      '!profile_namePlural' => '!profile_namePlural',
    );

    $servers = ldap_servers_get_servers(NULL, 'enabled');
    $server_options = array();
    foreach ($servers as $id => $server) {
      $server_options[$id] = $server->label() . ' (' . $server->address . ')';
    }

    $form['status'] = array(
      '#type' => 'fieldset',
      '#title' => t('I.  Basics'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );

    if ( count($server_options) ) {
      if (count($server_options) == 1) {
        $this->configuration['server'] = key($server_options);
      }
      $form['status']['server'] = array(
        '#type' => 'radios',
        '#title' => t('LDAP Server used in !profile_name configuration.', $provider_tokens),
        '#required' => 1,
        '#default_value' => $this->configuration['status']['server'],
        '#options' => $server_options,
      );
    } else {
      $form['status']['server'] = array(
        '#type' => 'markup',
        '#markup' => t('<strong>Warning</strong>: You must create an LDAP Server first.'),
      );
      drupal_set_message(t('You must create an LDAP Server first.'), 'warning');
    }

    $form['status']['type'] = array(
      '#type' => 'hidden',
      '#value' =>  $this->configuration['status']['type'],
      '#required' => 1,
    );

    $form['status']['only_ldap_authenticated'] = array(
      '#type' => 'checkbox',
      '#title' => t('Only apply the following LDAP to !profile_name configuration to users authenticated via LDAP.  On uncommon reason for disabling this is when you are using Drupal authentication, but want to leverage LDAP for authorization; for this to work the Drupal username still has to map to an LDAP entry.', $provider_tokens),
      '#default_value' =>  $this->configuration['status']['only_ldap_authenticated'],
    );


    if (method_exists($this->consumer, 'mappingExamples')) {
      $provider_tokens['!examples'] = '<fieldset class="collapsible collapsed form-wrapper" id="authorization-mappings">
<legend><span class="fieldset-legend">' . t('Examples based on current !profile_namePlural', $provider_tokens) . '</span></legend>
<div class="fieldset-wrapper">'. $this->consumer->mappingExamples($provider_tokens) . '<div class="fieldset-wrapper">
</fieldset>';
    }
    else {
      $provider_tokens['!examples'] = '';
    }
    $form['filter_and_mappings'] = array(
      '#type' => 'fieldset',
      '#title' => t('II. LDAP to !profile_name mapping and filtering', $provider_tokens),
      '#description' => t('
Representations of groups derived from LDAP might initially look like:
<ul>
<li><code>cn=students,ou=groups,dc=hogwarts,dc=edu</code></li>
<li><code>cn=gryffindor,ou=groups,dc=hogwarts,dc=edu</code></li>
<li><code>cn=faculty,ou=groups,dc=hogwarts,dc=edu</code></li>
<li><code>cn=probation students,ou=groups,dc=hogwarts,dc=edu</code></li>
</ul>

<p><strong>Mappings are used to convert and filter these group representations to !profile_namePlural.</strong></p>

!consumer_mappingDirections

!examples

', $provider_tokens),
      '#collapsible' => TRUE,
      '#collapsed' => !($this->mappings || $this->useMappingsAsFilter || $this->useFirstAttrAsGroupId),
    );

    $form['filter_and_mappings']['use_first_attr_as_groupid'] = array(
      '#type' => 'checkbox',
      '#title' => t('Convert full dn to value of first attribute before mapping.  e.g.  <code>cn=students,ou=groups,dc=hogwarts,dc=edu</code> would be converted to <code>students</code>', $provider_tokens),
      '#default_value' => $this->configuration['filter_and_mappings']['use_first_attr_as_groupid'],
    );

    $form['filter_and_mappings']['mappings'] = array(
      '#type' => 'textarea',
      '#title' => t('Mapping of LDAP to !profile_name (one per line)', $provider_tokens),
      '#default_value' => $this->mappingsToPipeList($this->configuration['filter_and_mappings']['mappings']),
      '#cols' => 50,
      '#rows' => 5,
    );

    $form['filter_and_mappings']['use_filter'] = array(
      '#type' => 'checkbox',
      '#title' => t('Only grant !profile_namePlural that match a filter above.', $provider_tokens),
      '#default_value' => $this->configuration['filter_and_mappings']['use_filter'],
      '#description' => t('If enabled, only above mapped !profile_namePlural will be assigned (e.g. students and administrator).
        <strong>If not checked, !profile_namePlural not mapped above also may be created and granted (e.g. gryffindor and probation students).  In some LDAPs this can lead to hundreds of !profile_namePlural being created if "Create !profile_namePlural if they do not exist" is enabled below.
        </strong>', $provider_tokens)
    );

    $form['more'] = array(
      '#type' => 'fieldset',
      '#title' => t('Part III.  Even More Settings.'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );

    $synchronization_modes = array();
    $this->synchOnLogon = (bool)(@$this->configuration['more']['synchronization_modes']['user_logon']);
    if ($this->synchOnLogon)  {
      $synchronization_modes[] = 'user_logon';
    }
    $form['more']['synchronization_modes'] = array(
      '#type' => 'checkboxes',
      '#title' => t('When should !profile_namePlural be granted/revoked from user?', $provider_tokens),
      '#options' => array(
          'user_logon' => t('When a user logs on.'),
      ),
      '#default_value' => $synchronization_modes,
      '#description' => '',
    );

    $synchronization_actions = array();
    if ($this->configuration['more']['synchronization_actions']['revoke_ldap_provisioned'])  {
      $synchronization_actions[] = 'revoke_ldap_provisioned';
    }
    if ($this->configuration['more']['synchronization_actions']['create_consumers'])  {
      $synchronization_actions[] = 'create_consumers';
    }
    if ($this->configuration['more']['synchronization_actions']['regrant_ldap_provisioned'])  {
      $synchronization_actions[] = 'regrant_ldap_provisioned';
    }

    $options =  array(
      'revoke_ldap_provisioned' => t('Revoke !profile_namePlural previously granted by LDAP Authorization but no longer valid.', $provider_tokens),
      'regrant_ldap_provisioned' => t('Re grant !profile_namePlural previously granted by LDAP Authorization but removed manually.', $provider_tokens),
    );
    // Move to consumer
    if ($this->consumer->allowConsumerObjectCreation) {
      $options['create_consumers'] = t('Create !profile_namePlural if they do not exist.', $provider_tokens);
    }

    $form['more']['synchronization_actions'] = array(
      '#type' => 'checkboxes',
      '#title' => t('What actions would you like performed when !profile_namePlural are granted/revoked from user?', $provider_tokens),
      '#options' => $options,
      '#default_value' => $synchronization_actions,
    );
    /**
     * @todo  some general options for an individual mapping (perhaps in an advance tab).
     *
     * - on synchronization allow: revoking authorizations made by this module, authorizations made outside of this module
     * - on synchronization create authorization contexts not in existance when needed (drupal roles etc)
     * - synchronize actual authorizations (not cached) when granting authorizations
     */

    return $form;
  }


  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    $mappings = $values['filter_and_mappings']['mappings'];
    $mappings = $this->normalizeMappings($this->pipeListToArray($mappings, TRUE));
    $values['filter_and_mappings']['mappings'] = $mappings;
    $form_state->setValues($values);
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    // @TODO what does this do?

    // Since the form is nested into another, we can't simply use #parents for
    // doing this array restructuring magic. (At least not without creating an
    // unnecessary dependency on internal implementation.)
    // $values += $values['test'];
    // $values += $values['advanced'];
    // $values += !empty($values['autocomplete']) ? $values['autocomplete'] : array();
    // unset($values['test'], $values['advanced'], $values['autocomplete']);

    // // Highlighting retrieved data only makes sense when we retrieve data.
    // $values['highlight_data'] &= $values['retrieve_data'];

    // // For password fields, there is no default value, they're empty by default.
    // // Therefore we ignore empty submissions if the user didn't change either.
    // if ($values['http_pass'] === ''
    //     && isset($this->configuration['http_user'])
    //     && $values['http_user'] === $this->configuration['http_user']) {
    //   $values['http_pass'] = $this->configuration['http_pass'];
    // }

    foreach ($values as $key => $value) {
      $form_state->setValue($key, $value);
    }

    parent::submitConfigurationForm($form, $form_state);
  }


  public function buildRowForm(array $form, FormStateInterface $form_state, $index) {
    $row = array();
    $row['query'] = array(
      '#type' => 'textfield',
      '#title' => t('LDAP query'),
      '#default_value' => $this->configuration['query'],
    );
    return $row;
  }

  public function buildRowDescription() {
    return '
      Representations of groups derived from LDAP might initially look like:
      <ul>
        <li><code>cn=students,ou=groups,dc=hogwarts,dc=edu</code></li>
        <li><code>cn=gryffindor,ou=groups,dc=hogwarts,dc=edu</code></li>
        <li><code>cn=faculty,ou=groups,dc=hogwarts,dc=edu</code></li>
        <li><code>cn=probation students,ou=groups,dc=hogwarts,dc=edu</code></li>
      </ul>
      ';
  }

  protected function mappingsToPipeList($mappings) {
    $result_text = "";
    foreach ($mappings as $map) {
      $result_text .= $map['from'] . '|' . $map['user_entered'] . "\n";
    }
    return $result_text;
  }

  protected function pipeListToArray($mapping_list_txt, $make_item0_lowercase = FALSE) {
    $result_array = array();
    $mappings = preg_split('/[\n\r]+/', $mapping_list_txt);
    foreach ($mappings as $line) {
      if (count($mapping = explode('|', trim($line))) == 2) {
        $item_0 = ($make_item0_lowercase) ? \Drupal\Component\Utility\Unicode::strtolower(trim($mapping[0])) : trim($mapping[0]);
        $result_array[] = array($item_0, trim($mapping[1]));
      }
    }
    return $result_array;
  }


 /**
   * @see LdapAuthorizationConsumerAbstract::normalizeMappings
   */
  public function normalizeMappings($mappings) {
    $new_mappings = array();
    $roles_by_name = user_roles(TRUE); // in rid => role name format
    foreach ($mappings as $i => $mapping) {
      $new_mapping = array();
      $new_mapping['user_entered'] = $mapping[1];
      $new_mapping['from'] = $mapping[0];
      $new_mapping['normalized'] = $mapping[1];
      $new_mapping['simplified'] = $mapping[1];
      $create_consumers = (boolean)($this->allowConsumerObjectCreation && $this->consumerConf->createConsumers);
      $new_mapping['valid'] = (boolean)(!$create_consumers && !empty($roles_by_name[$mapping[1]]));
      $new_mapping['error_message'] = ($new_mapping['valid']) ? '' : t("Role %role_name does not exist and role creation is not enabled.", array('%role' => $mapping[1]));
      $new_mappings[] = $new_mapping;
    }

    return $new_mappings;
  }
}
