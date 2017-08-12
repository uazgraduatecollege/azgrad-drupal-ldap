<?php

namespace Drupal\ldap_authorization\Plugin\authorization\Provider;

use Drupal\authorization\AuthorizationSkipAuthorization;
use Drupal\Component\Utility\Unicode;
use Drupal\Core\Form\FormStateInterface;
use Drupal\authorization\Provider\ProviderPluginBase;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;

/**
 * The LDAP authorization provider for authorization module.
 *
 * @AuthorizationProvider(
 *   id = "ldap_provider",
 *   label = @Translation("LDAP Authorization"),
 *   description = @Translation("Provider for LDAP group authorization.")
 * )
 */
class LDAPAuthorizationProvider extends ProviderPluginBase {

  public $providerType = 'ldap';
  public $handlers = ['ldap', 'ldap_authentication'];

  public $syncOnLogon = TRUE;

  public $revokeProviderProvisioned;
  public $regrantProviderProvisioned;

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    /** @var \Drupal\authorization\Entity\AuthorizationProfile $profile */
    $profile = $this->configuration['profile'];
    $tokens = $this->getTokens();
    $tokens += $profile->getTokens();
    if ($profile->hasValidConsumer() && method_exists($profile->getConsumer(), 'getTokens')) {
      $tokens += $profile->getConsumer()->getTokens();
    }

    $factory = \Drupal::service('ldap.servers');
    $servers = $factory->getEnabledServers();

    $form['status'] = [
      '#type' => 'fieldset',
      '#title' => t('Base configuration'),
      '#collapsible' => TRUE,
      '#collapsed' => FALSE,
    ];

    if (count($servers) == 0) {
      $form['status']['server'] = [
        '#type' => 'markup',
        '#markup' => t('<strong>Warning</strong>: You must create an LDAP Server first.'),
      ];
      drupal_set_message(t('You must create an LDAP Server first.'), 'warning');
    }
    else {
      $server_options = [];
      foreach ($servers as $id => $server) {
        /** @var \Drupal\ldap_servers\Entity\Server $server */
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
      $form['status']['server'] = [
        '#type' => 'radios',
        '#title' => t('LDAP Server used in @profile_name configuration.', $tokens),
        '#required' => 1,
        '#default_value' => $default_server,
        '#options' => $server_options,
      ];
    }

    $form['status']['only_ldap_authenticated'] = [
      '#type' => 'checkbox',
      '#title' => t('Only apply the following <strong>LDAP</strong> to <strong>@consumer_name</strong> configuration to users authenticated via LDAP', $tokens),
      '#description' => t('One uncommon reason for disabling this is when you are using Drupal authentication, but want to leverage LDAP for authorization; for this to work the Drupal username still has to map to an LDAP entry.'),
      '#default_value' => isset($provider_config['status'], $provider_config['status']['only_ldap_authenticated']) ? $provider_config['status']['only_ldap_authenticated'] : '',
    ];

    $form['filter_and_mappings'] = [
      '#type' => 'fieldset',
      '#title' => t('LDAP to @consumer_name mapping and filtering', $tokens),
      '#description' => t('Representations of groups derived from LDAP might initially look like:
        <ul>
        <li><code>cn=students,ou=groups,dc=hogwarts,dc=edu</code></li>
        <li><code>cn=gryffindor,ou=groups,dc=hogwarts,dc=edu</code></li>
        <li><code>cn=faculty,ou=groups,dc=hogwarts,dc=edu</code></li>
        </ul>
        <strong>Warning: If you enable "Create <em>@consumer_namePlural</em> if they do not exist" under conditions, all LDAP groups will be synced!</strong>', $tokens),
      '#collapsible' => TRUE,
    ];

    $form['filter_and_mappings']['use_first_attr_as_groupid'] = [
      '#type' => 'checkbox',
      '#title' => t('Convert full DN to value of first attribute before mapping'),
      '#description' => t('Example: <code>cn=students,ou=groups,dc=hogwarts,dc=edu</code> would be converted to <code>students</code>'),
      '#default_value' => isset($provider_config['filter_and_mappings'], $provider_config['filter_and_mappings']['use_first_attr_as_groupid']) ? $provider_config['filter_and_mappings']['use_first_attr_as_groupid'] : '',
    ];

    return $form;
  }

  /**
   * Build the form for the individual row.
   *
   * @param array $form
   *   Form.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   Form state.
   * @param int $index
   *   Index.
   *
   * @return array
   *   Returns form row.
   */
  public function buildRowForm(array $form, FormStateInterface $form_state, $index = 0) {
    $row = [];
    /** @var \Drupal\authorization\Entity\AuthorizationProfile $profile */
    $profile = $this->configuration['profile'];
    $mappings = $profile->getProviderMappings();
    $row['query'] = [
      '#type' => 'textfield',
      '#title' => t('LDAP query'),
      '#default_value' => isset($mappings[$index]) ? $mappings[$index]['query'] : NULL,
    ];
    $row['is_regex'] = [
      '#type' => 'checkbox',
      '#title' => t('Is this query a regular expression?'),
      '#default_value' => isset($mappings[$index]) ? $mappings[$index]['is_regex'] : NULL,
    ];

    return $row;
  }

  /**
   * Get valid proposals.
   *
   * @param \Drupal\user\Entity\User|mixed $user
   *   Drupal user.
   * @param mixed $op
   *   Operation, unknown, unused.
   * @param mixed $identifier
   *   Module identifier, unknown, unused.
   *
   * @return array|null
   *   Returns proposals.
   *
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
    /** @var \Drupal\authorization\Entity\AuthorizationProfile $profile */
    $profile = $this->configuration['profile'];
    $config = $profile->getProviderConfig();

    // Load the correct server.
    $server_id = $config['status']['server'];
    $factory = \Drupal::service('ldap.servers');
    /** @var \Drupal\ldap_servers\Entity\Server $server */
    $server = $factory->getServerByIdEnabled($server_id);
    $ldapUserData = $factory->getUserDataFromServerByAccount($user, $server_id);

    if (!$ldapUserData && $this->configuration['status']['only_ldap_authenticated'] == TRUE) {
      throw new AuthorizationSkipAuthorization();
    }

    // Get user groups from DN.
    $derive_from_dn_authorizations = $server->groupUserMembershipsFromDn($user);
    if (!$derive_from_dn_authorizations) {
      $derive_from_dn_authorizations = [];
    }

    // Get user groups from membership.
    $group_dns = $server->groupMembershipsFromUser($user);
    if (!$group_dns) {
      $group_dns = [];
    }

    $proposed_ldap_authorizations = array_merge($derive_from_dn_authorizations, $group_dns);
    $proposed_ldap_authorizations = array_unique($proposed_ldap_authorizations);
    if (\Drupal::config('ldap_help.settings')->get('watchdog_detail')) {
      \Drupal::logger('ldap_authorization')->debug(
        'Available authorizations to test: @authorizations',
        ['@authorizations' => implode("\n", $proposed_ldap_authorizations)]
      );
    }

    return (count($proposed_ldap_authorizations)) ? array_combine($proposed_ldap_authorizations, $proposed_ldap_authorizations) : [];
  }

  /**
   * Filter the proposals.
   *
   * @param array|mixed $proposed_ldap_authorizations
   *   Authorizations to check.
   * @param null|string $op
   *   Operation to apply it on.
   * @param array|mixed $provider_mapping
   *   The provider mapping.
   *
   * @return array
   *   Filtered proposals.
   */
  public function filterProposals($proposed_ldap_authorizations, $op, $provider_mapping) {
    $filtered_proposals = [];
    foreach ($proposed_ldap_authorizations as $key => $value) {
      if ($provider_mapping['is_regex']) {
        $pattern = $provider_mapping['query'];
        try {
          if (preg_match($pattern, $value, $matches)) {
            // If there is a sub-pattern then return the first one.
            // @TODO support named sub-patterns.
            if (count($matches) > 1) {
              $filtered_proposals[$key] = $matches[1];
            }
            else {
              $filtered_proposals[$key] = $value;
            }
          }
        }
        catch (\Exception $e) {
          \Drupal::logger('ldap')
            ->error('Error in matching regular expression @regex',
              ['@regex' => $pattern]
            );
        }
      }
      elseif ($value == $provider_mapping['query']) {
        $filtered_proposals[$key] = $value;
      }
    }
    return $filtered_proposals;
  }

  /**
   * Sanitizes given proposals.
   *
   * @param array|mixed $proposals
   *   Proposals to sanitize.
   * @param mixed $op
   *   Operation, unknown, unused.
   *
   * @return array
   *   Sanitized proposals.
   */
  public function sanitizeProposals($proposals, $op = NULL) {
    // Configure this provider.
    /** @var \Drupal\authorization\Entity\AuthorizationProfile $profile */
    $profile = $this->configuration['profile'];
    $config = $profile->getProviderConfig();
    $factory = \Drupal::service('ldap.servers');
    foreach ($proposals as $key => $authorization_id) {
      if ($config['filter_and_mappings']['use_first_attr_as_groupid']) {
        $attr_parts = $factory->ldapExplodeDn($authorization_id, 0);
        if (count($attr_parts) > 0) {
          $first_part = explode('=', $attr_parts[0]);
          if (count($first_part) > 1) {
            // @FIXME: Potential bug on trim.
            $authorization_id = ConversionHelper::unescapeDnValue(trim($first_part[1]));
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
   * Validates the form row.
   */
  public function validateRowForm(array &$form, FormStateInterface $form_state) {
    parent::validateRowForm($form, $form_state);

    foreach ($form_state->getValues() as $value) {
      if (isset($value['provider_mappings'])) {
        if ($value['provider_mappings']['is_regex'] == 1) {
          if (@preg_match($value['provider_mappings']['query'], NULL) === FALSE) {
            $form_state->setErrorByName('mapping', t('Invalid regular expression'));
          }
        }
      }
    }
  }

}
