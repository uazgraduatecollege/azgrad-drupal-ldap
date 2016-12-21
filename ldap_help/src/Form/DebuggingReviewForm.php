<?php

namespace Drupal\ldap_help\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\ConfigFormBase;
use \Drupal\Core\Config\ConfigFactoryInterface;

use Drupal\ldap_user\LdapUserConf;

/**
 *
 */
class DebuggingReviewForm extends ConfigFormBase {

  protected $LdapUserConfHelper;

  protected $drupalAcctProvisionServerOptions;
  protected $ldapEntryProvisionServerOptions;

  /**
   * {@inheritdoc}
   */
  public function __construct(ConfigFactoryInterface $config_factory) {
    parent::__construct($config_factory);

    $this->LdapUserConfHelper = new LdapUserConf();

  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_help_debugging_review';
  }

  /**
   * {@inheritdoc}
   */
  public function getEditableConfigNames() {
    return ['ldap_user.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('ldap_user.settings');

    $form['intro'] = array(
      '#type' => 'item',
      '#markup' => t('<h1>LDAP Debugging Review</h1>'),
    );

    // TODO: Add form from ldap_help.status.inc.

    return $form;
  }

}
