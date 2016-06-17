<?php

namespace Drupal\ldap_authorization\Plugin\authorization\provider;

use Drupal\Component\Utility\Unicode;
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

  public $providerType = 'ldap';
  public $handlers = array('ldap', 'ldap_authentication');

  public $synchOnLogon = TRUE;

  /**
   *
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $profile = $this->configuration['profile'];

    $tokens = $this->getTokens();
    $tokens += $profile->getTokens();
    if ($profile->hasValidConsumer()) {
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

    if (count($server_options)) {
      if (count($server_options) == 1) {
        $this->configuration['server'] = key($server_options);
      }
      $form['status']['server'] = array(
        '#type' => 'radios',
        '#title' => t('LDAP Server used in @profile_name configuration.', $tokens),
        '#required' => 1,
        '#default_value' => $this->configuration['status']['server'],
        '#options' => $server_options,
      );
    }
    else {
      $form['status']['server'] = array(
        '#type' => 'markup',
        '#markup' => t('<strong>Warning</strong>: You must create an LDAP Server first.'),
      );
      drupal_set_message(t('You must create an LDAP Server first.'), 'warning');
    }

    $form['status']['type'] = array(
      '#type' => 'hidden',
      '#value' => $this->configuration['status']['type'],
      '#required' => 1,
    );

    $form['status']['only_ldap_authenticated'] = array(
      '#type' => 'checkbox',
      '#title' => t('Only apply the following LDAP to @consumer_name configuration to users authenticated via LDAP.  On uncommon reason for disabling this is when you are using Drupal authentication, but want to leverage LDAP for authorization; for this to work the Drupal username still has to map to an LDAP entry.', $tokens),
      '#default_value' => $this->configuration['status']['only_ldap_authenticated'],
    );

    if (method_exists($this->consumer, 'mappingExamples')) {
      $tokens['@examples'] = '<fieldset class="collapsible collapsed form-wrapper" id="authorization-mappings">
<legend><span class="fieldset-legend">' . t('Examples based on current @profile_namePlural', $tokens) . '</span></legend>
<div class="fieldset-wrapper">' . $this->consumer->mappingExamples($tokens) . '<div class="fieldset-wrapper">
</fieldset>';
    }
    else {
      $tokens['@examples'] = '';
    }
    $form['filter_and_mappings'] = array(
      '#type' => 'fieldset',
      '#title' => t('II. LDAP to @consumer_name mapping and filtering', $tokens),
      '#description' => t('
Representations of groups derived from LDAP might initially look like:
<ul>
<li><code>cn=students,ou=groups,dc=hogwarts,dc=edu</code></li>
<li><code>cn=gryffindor,ou=groups,dc=hogwarts,dc=edu</code></li>
<li><code>cn=faculty,ou=groups,dc=hogwarts,dc=edu</code></li>
<li><code>cn=probation students,ou=groups,dc=hogwarts,dc=edu</code></li>
</ul>

<p><strong>Mappings are used to convert and filter these group representations to @consumer_namePlural.</strong></p>

@consumer_mappingDirections

@examples

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
      '#title' => t('Only grant @consumer_namePlural that match a filter below.', $tokens),
      '#default_value' => $this->configuration['filter_and_mappings']['use_filter'],
      '#description' => t('If enabled, only below mapped @consumer_namePlural will be assigned (e.g. students and administrator).
        <strong>If not checked, @consumer_namePlural not mapped below also may be created and granted (e.g. gryffindor and probation students).  In some LDAPs this can lead to hundreds of @consumer_namePlural being created if "Create @consumer_namePlural if they do not exist" is enabled below.
        </strong>', $tokens),
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
    // unset($values['test'], $values['advanced'], $values['autocomplete']);.
    // // Highlighting retrieved data only makes sense when we retrieve data.
    // $values['highlight_data'] &= $values['retrieve_data'];.
    // // For password fields, there is no default value, they're empty by default.
    // // Therefore we ignore empty submissions if the user didn't change either.
    // if ($values['http_pass'] === ''
    //     && isset($this->configuration['http_user'])
    //     && $values['http_user'] === $this->configuration['http_user']) {
    //   $values['http_pass'] = $this->configuration['http_pass'];
    // }.
    foreach ($values as $key => $value) {
      $form_state->setValue($key, $value);
    }

    parent::submitConfigurationForm($form, $form_state);
  }

  /**
   *
   */
  public function buildRowForm(array $form, FormStateInterface $form_state, $index) {
    $row = array();
    $mappings = $this->configuration['profile']->getProviderMappings();
    $row['query'] = array(
      '#type' => 'textfield',
      '#title' => t('LDAP query'),
      '#default_value' => $mappings[$index]['query'],
    );
    $row['is_regex'] = array(
      '#type' => 'checkbox',
      '#title' => t('Is this query a regular expression?'),
      '#default_value' => $mappings[$index]['is_regex'],
    );

    return $row;
  }

  /**
   *
   */
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

  /**
   *
   */
  public function getProposals($user, $op, $identifier) {
    // In 7.x-2.x we get groups from Server via three methods
    // and then filter out the ones we don't want
    // https://www.drupal.org/node/1498558
    // Server->groupUserMembershipsFromDn($user)
    // https://www.drupal.org/node/1487018
    // https://www.drupal.org/node/1499172
    // Server->groupMembershipsFromUser($user, 'group_dns')
    // So what does the 'query' do then? Is it the filter?
    // Configure this provider.
    $profile = $this->configuration['profile'];
    $config = $profile->getProviderConfig();

    // Load the correct server.
    $server_id = $config['status']['server'];
    $ldap_server = \Drupal::entityManager()->getStorage('ldap_server')->load($server_id);

    // Get user data.
    $ldap_user = ldap_servers_get_user_ldap_data($user, $server_id);
    // Get user groups from DN.
    $derive_from_dn_authorizations = $ldap_server->groupUserMembershipsFromDn($user);
    if (!$derive_from_dn_authorizations) {
      $derive_from_dn_authorizations = array();
    }

    // Get user groups from membership.
    $group_dns = $ldap_server->groupMembershipsFromUser($user);
    if (!$group_dns) {
      $group_dns = array();
    }

    $proposed_ldap_authorizations = array_merge($derive_from_dn_authorizations, $group_dns);
    $proposed_ldap_authorizations = array_unique($proposed_ldap_authorizations);

    return (count($proposed_ldap_authorizations)) ? array_combine($proposed_ldap_authorizations, $proposed_ldap_authorizations) : array();
  }

  /**
   *
   */
  public function filterProposals($proposed_ldap_authorizations, $op = NULL, $provider_mapping) {
    // Configure this provider.
    $profile = $this->configuration['profile'];
    $config = $profile->getProviderConfig();

    $filtered_proposals = array();
    foreach ($proposed_ldap_authorizations as $key => $value) {
      // Match regular expressions.
      if ($provider_mapping['is_regex']) {
        $pattern = $provider_mapping['query'];
        try {
          if (preg_match($pattern, $value, $matches)) {
            // If there is a subpattern then return the first one.
            // @TODO support named subpatterns
            if (count($matches) > 1) {
              $filtered_proposals[$key] = $matches[1];
            }
            else {
              $filtered_proposals[$key] = $value;
            }
          }
        }
        catch (Exception $e) {
          // @TODO log errors.
        }
      }
      elseif ($value == $provider_mapping['query']) {
        $filtered_proposals[$key] = $value;
      }
    }
    return $filtered_proposals;
  }

  /**
   *
   */
  public function sanitizeProposals($proposals, $op = NULL) {
    // Configure this provider.
    $profile = $this->configuration['profile'];
    $config = $profile->getProviderConfig();

    foreach ($proposals as $key => $authorization_id) {
      if ($config['filter_and_mappings']['use_first_attr_as_groupid']) {
        $attr_parts = ldap_explode_dn($authorization_id, 0);
        if (count($attr_parts) > 0) {
          $first_part = explode('=', $attr_parts[0]);
          if (count($first_part) > 1) {
            $authorization_id = ldap_pear_unescape_dn_value(trim($first_part[1]));
          }
        }
        $new_key = Unicode::strtolower($authorization_id);
      }
      else {
        $new_key = Unicode::strtolower($key);
      }
      $proposals[$new_key] = $authorization_id;
      if ($key != $new_key) {
        unset($proposals[$key]);
      }
    }
    return $proposals;
  }

  /**
   *
   */
  protected function mappingsToPipeList($mappings) {
    $result_text = "";
    foreach ($mappings as $map) {
      $result_text .= $map['from'] . '|' . $map['user_entered'] . "\n";
    }
    return $result_text;
  }

  /**
   *
   */
  protected function pipeListToArray($mapping_list_txt, $make_item0_lowercase = FALSE) {
    $result_array = array();
    $mappings = preg_split('/[\n\r]+/', $mapping_list_txt);
    foreach ($mappings as $line) {
      if (count($mapping = explode('|', trim($line))) == 2) {
        $item_0 = ($make_item0_lowercase) ? Unicode::strtolower(trim($mapping[0])) : trim($mapping[0]);
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
    // In rid => role name format.
    $roles_by_name = user_roles(TRUE);
    foreach ($mappings as $i => $mapping) {
      $new_mapping = array();
      $new_mapping['user_entered'] = $mapping[1];
      $new_mapping['from'] = $mapping[0];
      $new_mapping['normalized'] = $mapping[1];
      $new_mapping['simplified'] = $mapping[1];
      $new_mapping['valid'] = (boolean) (!$create_consumers && !empty($roles_by_name[$mapping[1]]));
      $new_mapping['error_message'] = ($new_mapping['valid']) ? '' : t("Role %role_name does not exist and role creation is not enabled.", array('%role' => $mapping[1]));
      $new_mappings[] = $new_mapping;
    }

    return $new_mappings;
  }

}
