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
  public $handlers = array('ldap', 'ldap_authentication');

  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $profile = $this->configuration['profile'];

    $tokens = $this->getTokens();
    $tokens += $profile->getTokens();
    if ( $profile->hasValidConsumer() ) {
      $tokens += $profile->getConsumer()->getTokens();
    }

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
        '#title' => t('LDAP Server used in !profile_name configuration.', $tokens),
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
      '#title' => t('Only apply the following LDAP to !consumer_name configuration to users authenticated via LDAP.  On uncommon reason for disabling this is when you are using Drupal authentication, but want to leverage LDAP for authorization; for this to work the Drupal username still has to map to an LDAP entry.', $tokens),
      '#default_value' =>  $this->configuration['status']['only_ldap_authenticated'],
    );


    if (method_exists($this->consumer, 'mappingExamples')) {
      $tokens['!examples'] = '<fieldset class="collapsible collapsed form-wrapper" id="authorization-mappings">
<legend><span class="fieldset-legend">' . t('Examples based on current !profile_namePlural', $tokens) . '</span></legend>
<div class="fieldset-wrapper">'. $this->consumer->mappingExamples($tokens) . '<div class="fieldset-wrapper">
</fieldset>';
    }
    else {
      $tokens['!examples'] = '';
    }
    $form['filter_and_mappings'] = array(
      '#type' => 'fieldset',
      '#title' => t('II. LDAP to !consumer_name mapping and filtering', $tokens),
      '#description' => t('
Representations of groups derived from LDAP might initially look like:
<ul>
<li><code>cn=students,ou=groups,dc=hogwarts,dc=edu</code></li>
<li><code>cn=gryffindor,ou=groups,dc=hogwarts,dc=edu</code></li>
<li><code>cn=faculty,ou=groups,dc=hogwarts,dc=edu</code></li>
<li><code>cn=probation students,ou=groups,dc=hogwarts,dc=edu</code></li>
</ul>

<p><strong>Mappings are used to convert and filter these group representations to !consumer_namePlural.</strong></p>

!consumer_mappingDirections

!examples

', $tokens),
      '#collapsible' => TRUE,
      '#collapsed' => !($this->mappings || $this->useMappingsAsFilter || $this->useFirstAttrAsGroupId),
    );

    $form['filter_and_mappings']['use_first_attr_as_groupid'] = array(
      '#type' => 'checkbox',
      '#title' => t('Convert full dn to value of first attribute before mapping.  e.g.  <code>cn=students,ou=groups,dc=hogwarts,dc=edu</code> would be converted to <code>students</code>', $tokens),
      '#default_value' => $this->configuration['filter_and_mappings']['use_first_attr_as_groupid'],
    );

    $form['filter_and_mappings']['use_filter'] = array(
      '#type' => 'checkbox',
      '#title' => t('Only grant !consumer_namePlural that match a filter above.', $tokens),
      '#default_value' => $this->configuration['filter_and_mappings']['use_filter'],
      '#description' => t('If enabled, only above mapped !consumer_namePlural will be assigned (e.g. students and administrator).
        <strong>If not checked, !consumer_namePlural not mapped above also may be created and granted (e.g. gryffindor and probation students).  In some LDAPs this can lead to hundreds of !consumer_namePlural being created if "Create !consumer_namePlural if they do not exist" is enabled below.
        </strong>', $tokens)
    );

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
    $mappings = $this->configuration['profile']->getProviderMappings();
    $row['query'] = array(
      '#type' => 'textfield',
      '#title' => t('LDAP query'),
      '#default_value' => $mappings[$index]['query'],
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
      Also supports regular expressions. For example:
        <code>cn=.*,ou=groups,dc=hogwarts,dc=edu</code>
      ';
  }

  public function apply($user, $op, $identifier, $provider_mapping) {
    if ( empty($provider_mapping['query']) ) {
      return;
    }
    // Configure this provider
    $profile = $this->configuration['profile'];
    $config = $profile->getProviderConfig();

    // Load the correct server
    $server_id = $config['status']['server'];
    $ldap_server = \Drupal::entityManager()->getStorage('ldap_server')->load($server_id);

    // Get user data
    $ldap_user = ldap_servers_get_user_ldap_data($user, $server_id);

    $result_array = array();
    // Iterate memberOf looking for matches from the LDAP configuration
    // Get the memberof key from the server config entity
    $groupUserMembershipsAttr = $ldap_server->get('grp_user_memb_attr');
    foreach ( $ldap_user['attr'][$groupUserMembershipsAttr] as $dn ) {
      // @TODO Just replace '=' with '\=' instead
      $pattern = "/^" . preg_quote($provider_mapping['query']) . "$/";
      if ( preg_match($pattern, $dn, $matches) ) {
        $result_array[] = $dn;
      }
    }
    return $result_array;
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
