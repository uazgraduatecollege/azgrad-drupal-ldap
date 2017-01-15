<?php

namespace Drupal\ldap_authorization\Plugin\authorization\provider;

use Drupal\authorization\AuthorizationSkipAuthorization;
use Drupal\authorization\Entity\AuthorizationProfile;
use Drupal\Component\Utility\Unicode;
use Drupal\Core\Form\FormStateInterface;

use Drupal\authorization\Provider\ProviderPluginBase;
use Drupal\ldap_servers\ConversionHelper;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;

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

  public $syncOnLogon = TRUE;

  public $revokeProviderProvisioned;
  public $regrantProviderProvisioned;

  /**
   *
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    /** @var AuthorizationProfile $profile */
    $profile = $this->configuration['profile'];
    $tokens = $this->getTokens();
    $tokens += $profile->getTokens();
    if ($profile->hasValidConsumer() && method_exists($profile->getConsumer(), 'getTokens')) {
      $tokens += $profile->getConsumer()->getTokens();
    }

    $factory = \Drupal::service('ldap.servers');
    $servers = $factory->getEnabledServers();

    $form['status'] = array(
      '#type' => 'fieldset',
      '#title' => t('Base configuration'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    );

    if (count($servers) == 0) {
      $form['status']['server'] = array(
        '#type' => 'markup',
        '#markup' => t('<strong>Warning</strong>: You must create an LDAP Server first.'),
      );
      drupal_set_message(t('You must create an LDAP Server first.'), 'warning');
    }
    else {
      $server_options = array();
      foreach ($servers as $id => $server) {
        /** @var Server $server */
        $server_options[$id] = $server->label() . ' (' . $server->get('address') . ')';
      }
    }

    $provider_config = $profile->getProviderConfig();

    if (!empty($server_options)) {
      if (isset($provider_config['status'])) {
        $default_server = $provider_config['status']['server'];
      }
      elseif (count($server_options) == 1) {
        $default_server = key($server_options);
      }
      else {
        $default_server = '';
      }
      $form['status']['server'] = array(
        '#type' => 'radios',
        '#title' => t('LDAP Server used in @profile_name configuration.', $tokens),
        '#required' => 1,
        '#default_value' => $default_server,
        '#options' => $server_options,
      );
    }

    $form['status']['only_ldap_authenticated'] = array(
      '#type' => 'checkbox',
      '#title' => t('Only apply the following <strong>LDAP</strong> to <strong>@consumer_name</strong> configuration to users authenticated via LDAP', $tokens),
      '#description' => t('One uncommon reason for disabling this is when you are using Drupal authentication, but want to leverage LDAP for authorization; for this to work the Drupal username still has to map to an LDAP entry.'),
      '#default_value' => isset($provider_config['status'], $provider_config['status']['only_ldap_authenticated']) ? $provider_config['status']['only_ldap_authenticated'] : '',
    );

    $form['filter_and_mappings'] = array(
      '#type' => 'fieldset',
      '#title' => t('LDAP to @consumer_name mapping and filtering', $tokens),
      '#description' => t('Representations of groups derived from LDAP might initially look like:
        <ul>
        <li><code>cn=students,ou=groups,dc=hogwarts,dc=edu</code></li>
        <li><code>cn=gryffindor,ou=groups,dc=hogwarts,dc=edu</code></li>
        <li><code>cn=faculty,ou=groups,dc=hogwarts,dc=edu</code></li>
        <li><code>cn=probation students,ou=groups,dc=hogwarts,dc=edu</code></li>
        </ul>
        <p><strong>Mappings are used to convert and filter these group representations to @consumer_namePlural.</strong></p> @consumer_mappingDirections', $tokens),
      '#collapsible' => TRUE,
    );

    $form['filter_and_mappings']['use_first_attr_as_groupid'] = array(
      '#type' => 'checkbox',
      '#title' => t('Convert full DN to value of first attribute before mapping'),
      '#description' => t('Example: <code>cn=students,ou=groups,dc=hogwarts,dc=edu</code> would be converted to <code>students</code>'),
      '#default_value' => isset($provider_config['filter_and_mappings'], $provider_config['filter_and_mappings']['use_first_attr_as_groupid']) ? $provider_config['filter_and_mappings']['use_first_attr_as_groupid'] : '',
    );

    $form['filter_and_mappings']['use_filter'] = array(
      '#type' => 'checkbox',
      '#title' => t('Only grant "@consumer_namePlural" that match a filter below.', $tokens),
      '#default_value' => isset($provider_config['filter_and_mappings'], $provider_config['filter_and_mappings']['use_filter']) ? $provider_config['filter_and_mappings']['use_filter'] : '',
      '#description' => t('If enabled, only below mapped @consumer_namePlural will be assigned (e.g. students and administrator).<br>
        <strong>If not checked, @consumer_namePlural not mapped below also may be created and granted (e.g. gryffindor and probation students).  In some LDAPs this can lead to hundreds of @consumer_namePlural being created if "Create @consumer_namePlural if they do not exist" is enabled below.</strong>',
        $tokens),
    );

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    if (isset($values['filter_and_mappings']['mappings'])) {
      // @FIXME: Mappings is never present, see if we can move this to authorization.
      $mappings = $values['filter_and_mappings']['mappings'];
      $mappings = $this->normalizeMappings($this->pipeListToArray($mappings, TRUE));
      $values['filter_and_mappings']['mappings'] = $mappings;
      $form_state->setValues($values);
    }
  }

  /**
   * @param array $form
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   * @param int $index
   * @return array
   */
  public function buildRowForm(array $form, FormStateInterface $form_state, $index = 0) {
    $row = array();
    /** @var AuthorizationProfile $this->configuration['profile'] */
    $mappings = $this->configuration['profile']->getProviderMappings();
    $row['query'] = array(
      '#type' => 'textfield',
      '#title' => t('LDAP query'),
      '#default_value' => isset($mappings[$index]) ? $mappings[$index]['query'] : NULL,
    );
    $row['is_regex'] = array(
      '#type' => 'checkbox',
      '#title' => t('Is this query a regular expression?'),
      '#default_value' => isset($mappings[$index]) ? $mappings[$index]['is_regex'] : NULL,
    );

    return $row;
  }

  /**
   * @param $user
   * @param $op
   * @param $identifier
   * @return array|null
   * @throws \Drupal\authorization\AuthorizationSkipAuthorization
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
    // Do not continue if user should be excluded from LDAP authentication.
    if (ExternalAuthenticationHelper::excludeUser($user)) {
      throw new AuthorizationSkipAuthorization();
    }
    /** @var AuthorizationProfile $profile */
    $profile = $this->configuration['profile'];
    $config = $profile->getProviderConfig();

    // Load the correct server.
    $server_id = $config['status']['server'];
    $factory = \Drupal::service('ldap.servers');
    /** @var Server $server */
    $server = $factory->getServerByIdEnabled($server_id);
    $ldapUserData = $factory->getUserDataFromServerByAccount($user, $server_id);

    if (!$ldapUserData && $this->configuration['status']['only_ldap_authenticated'] == TRUE) {
      throw new AuthorizationSkipAuthorization();
    }

    // Get user groups from DN.
    $derive_from_dn_authorizations = $server->groupUserMembershipsFromDn($user);
    if (!$derive_from_dn_authorizations) {
      $derive_from_dn_authorizations = array();
    }

    // Get user groups from membership.
    $group_dns = $server->groupMembershipsFromUser($user);
    if (!$group_dns) {
      $group_dns = array();
    }

    $proposed_ldap_authorizations = array_merge($derive_from_dn_authorizations, $group_dns);
    $proposed_ldap_authorizations = array_unique($proposed_ldap_authorizations);

    return (count($proposed_ldap_authorizations)) ? array_combine($proposed_ldap_authorizations, $proposed_ldap_authorizations) : array();
  }

  /**
   * @param $proposed_ldap_authorizations
   * @param null $op
   * @param $provider_mapping
   * @return array
   */
  public function filterProposals($proposed_ldap_authorizations, $op = NULL, $provider_mapping) {
    $filtered_proposals = [];
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
        catch (\Exception $e) {
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
   * @param $proposals
   * @param null $op
   */
  public function sanitizeProposals($proposals, $op = NULL) {
    // Configure this provider.
    /** @var AuthorizationProfile $profile */
    $profile = $this->configuration['profile'];
    $config = $profile->getProviderConfig();
    $factory = \Drupal::service('ldap.servers');
    foreach ($proposals as $key => $authorization_id) {
      if ($config['filter_and_mappings']['use_first_attr_as_groupid']) {
        $attr_parts = $factory->ldapExplodeDn($authorization_id, 0);
        if (count($attr_parts) > 0) {
          $first_part = explode('=', $attr_parts[0]);
          if (count($first_part) > 1) {
            $helper = new ConversionHelper();
            $authorization_id = $helper->unescape_dn_value(trim($first_part[1]));
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
   * @param $mappings
   * @return string
   */
  protected function mappingsToPipeList($mappings) {
    $result_text = "";
    foreach ($mappings as $map) {
      $result_text .= $map['from'] . '|' . $map['user_entered'] . "\n";
    }
    return $result_text;
  }

  /**
   * @param $mapping_list_txt
   * @param bool $make_item0_lowercase
   * @return array
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
   * @param $mappings
   * @return array
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
      $new_mapping['valid'] = (boolean) (!empty($roles_by_name[$mapping[1]]));
      $new_mapping['error_message'] = ($new_mapping['valid']) ? '' : t("Role %role_name does not exist and role creation is not enabled.", array('%role' => $mapping[1]));
      $new_mappings[] = $new_mapping;
    }

    return $new_mappings;
  }

}
