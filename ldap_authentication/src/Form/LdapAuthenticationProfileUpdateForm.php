<?php

namespace Drupal\ldap_authentication\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\FormBase;

/**
 *
 */
class LdapAuthenticationProfileUpdateForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_authentication_profile_update_form';
  }

  /**
   *
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $form['mail'] = [
      '#type' => 'textfield',
      '#required' => TRUE,
      '#title' => t('Email Address'),
    ];
    $form['submit'] = [
      '#type' => 'submit',
      '#value' => t('Update Profile'),
    ];
    return $form;
  }

  /**
   *
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    if (!filter_var($form_state->getValue(['mail']), FILTER_VALIDATE_EMAIL)) {
      $form_state->setErrorByName('mail', t('You must specify a valid email address.'));
    }
    $existing = user_load_by_mail($form_state->getValue(['mail']));
    if ($existing) {
      $form_state->setErrorByName('mail', t('This email address is already in user.'));
    }
    $auth = ldap_authentication_get_valid_conf();
    $regex = '`' . $auth->templateUsagePromptRegex . '`i';
    if (preg_match($regex, $form_state->getValue(['mail']))) {
      $form_state->setErrorByName('mail', t('This email address still matches the invalid email template.'));
    }
  }

  /**
   *
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $user = \Drupal::currentUser();
    // @FIXME
    // user_save() is now a method of the user entity.
    // if (user_save($user, array(
    //     'mail' => $form_state['values']['mail'],
    //   ))) {
    //     // prevents the cached setting from being used again.
    //     unset($_SESSION['ldap_authentication_template']);
    //     $form_state['redirect'] = isset($_GET['next']) ? $_GET['next'] : '<front>';
    //     drupal_set_message(t('Your profile has been updated.'));
    //   }
  }

}
