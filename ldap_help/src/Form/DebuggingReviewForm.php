<?php

namespace Drupal\ldap_help\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Serialization\Yaml;
use Drupal\ldap_query\Controller\QueryController;
use Drupal\ldap_servers\ServerFactory;

/**
 * Form to allow for debugging review.
 */
class DebuggingReviewForm extends FormBase {

  protected $ldapEntryProvisionServerOptions;

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_help_debugging_review';
  }

  /**
   * Returns raw data of configuration.
   *
   * @param string $configName
   *   Configuration name.
   *
   * @return string
   *   Raw configuration data.
   */
  private function printConfig($configName) {
    $config = \Drupal::configFactory()->get($configName);
    return '<pre>' . Yaml::encode($config->getRawData()) . '</pre>';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {

    $form['title'] = [
      '#markup' => '<h1>' . $this->t('LDAP Debugging Review') . '</h1>',
    ];

    if (!extension_loaded('ldap')) {
      drupal_set_message($this->t('PHP LDAP extension not loaded.'), 'error');
    }
    else {
      $form['heading_modules'] = [
        '#markup' => '<h2>' . $this->t('PHP LDAP module') . '</h2>',
      ];
      $form['modules'] = [
        '#markup' => '<pre>' . Yaml::encode($this->parsePhpModules()['ldap']) . '</pre>',
      ];
    }

    $form['heading_ldap'] = [
      '#markup' => '<h2>' . $this->t('Drupal LDAP modules') . '</h2>',
    ];

    if (\Drupal::moduleHandler()->moduleExists('ldap_user')) {
      $form['config_users'] = [
        '#markup' =>
        '<h3>' . $this->t('The LDAP user configuration') . '</h3>' .
        $this->printConfig('ldap_user.settings'),
      ];
    }

    $user_register = \Drupal::config('user.settings')->get('register');
    $form['config_users_registration'] = [
      '#markup' => $this->t('Currently active Drupal user registration setting: @setting', ['@setting' => $user_register]),
    ];

    if (\Drupal::moduleHandler()->moduleExists('ldap_authentication')) {
      $form['config_authentication'] = [
        '#markup' =>
        '<h3>' . $this->t('The LDAP authentication configuration') . '</h3>' .
        $this->printConfig('ldap_authentication.settings'),
      ];
    }

    if (\Drupal::moduleHandler()->moduleExists('ldap_help')) {
      $form['config_help'] = [
        '#markup' =>
        '<h3>' . $this->t('The LDAP help configuration') . '</h3>' .
        $this->printConfig('ldap_help.settings'),
      ];
    }

    if (\Drupal::moduleHandler()->moduleExists('ldap_servers')) {
      $form['heading_servers'] = [
        '#markup' => '<h2>' . $this->t('Drupal LDAP servers') . '</h2>',
      ];

      $servers = new ServerFactory();
      foreach ($servers->getAllServers() as $sid => $server) {
        /** @var \Drupal\ldap_servers\Entity\Server $server */
        $form['config_server_' . $sid] = [
          '#markup' =>
          '<h3>' . $this->t('Server @name:', ['@name' => $server->label()]) . '</h3>' .
          $this->printConfig('ldap_servers.server.' . $sid),
        ];
      }
    }

    if (\Drupal::moduleHandler()->moduleExists('authorization') &&
      \Drupal::moduleHandler()->moduleExists('ldap_authorization')) {
      $form['heading_profiles'] = [
        '#markup' => '<h2>' . $this->t('Configured authorization profiles') . '</h2>',
      ];

      foreach (authorization_get_profiles() as $profile) {
        $form['authorization_profile_' . $profile] = [
          '#markup' =>
          '<h3>' . $this->t('Profile @name:', ['@name' => $profile]) . '</h3>' .
          $this->printConfig('authorization.authorization_profile.' . $profile),
        ];
      }
    }

    if (\Drupal::moduleHandler()->moduleExists('ldap_query')) {
      $form['heading_queries'] = [
        '#markup' => '<h2>' . $this->t('Configured LDAP queries') . '</h2>',
      ];

      foreach (QueryController::getAllQueries() as $query) {
        /** @var \Drupal\ldap_query\Entity\QueryEntity $query */
        $form['query_' . $query->id()] = [
          '#markup' =>
          '<h3>' . $this->t('Query @name:', ['@name' => $query->label()]) . '</h3>' .
          $this->printConfig('ldap_query.ldap_query_entity.' . $query->id()),
        ];
      }
    }

    return $form;
  }

  /**
   * Generates an array of values from phpinfo().
   *
   * @return array
   *   Module list.
   */
  private function parsePhpModules() {
    ob_start();
    phpinfo();
    $s = ob_get_contents();
    ob_end_clean();

    $s = strip_tags($s, '<h2><th><td>');
    $s = preg_replace('/<th[^>]*>([^<]+)<\/th>/', "<info>\\1</info>", $s);
    $s = preg_replace('/<td[^>]*>([^<]+)<\/td>/', "<info>\\1</info>", $s);
    $vtmp = preg_split('/(<h2>[^<]+<\/h2>)/', $s, -1, PREG_SPLIT_DELIM_CAPTURE);
    $vmodules = [];
    for ($i = 1; $i < count($vtmp); $i++) {
      if (preg_match('/<h2>([^<]+)<\/h2>/', $vtmp[$i], $vmat)) {
        $vname = trim($vmat[1]);
        $vtmp2 = explode("\n", $vtmp[$i + 1]);
        foreach ($vtmp2 as $vone) {
          $vpat = '<info>([^<]+)<\/info>';
          $vpat3 = "/$vpat\s*$vpat\s*$vpat/";
          $vpat2 = "/$vpat\s*$vpat/";
          // 3cols.
          if (preg_match($vpat3, $vone, $vmat)) {
            $vmodules[$vname][trim($vmat[1])] = [trim($vmat[2]), trim($vmat[3])];
          }
          // 2cols.
          elseif (preg_match($vpat2, $vone, $vmat)) {
            $vmodules[$vname][trim($vmat[1])] = trim($vmat[2]);
          }
        }
      }
    }
    return $vmodules;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // Nothing to submit.
  }

}
