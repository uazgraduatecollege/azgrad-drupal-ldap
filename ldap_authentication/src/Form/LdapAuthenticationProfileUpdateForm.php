<?php

namespace Drupal\ldap_authentication\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\FormBase;
use Drupal\ldap_authentication\Routing\EmailTemplateService;
use Drupal\user\Entity\User;

/**
 * Profile update form.
 *
 * This form is meant to presented to the user if the LDAP account does not
 * have an e-mail address associated with it and we need it for Drupal
 * to function correctly, thus we ask the user.
 */
class LdapAuthenticationProfileUpdateForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_authentication_profile_update_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    if (EmailTemplateService::profileNeedsUpdate()) {
      $form['mail'] = [
        '#type' => 'textfield',
        '#required' => TRUE,
        '#title' => $this->t('Email address'),
      ];
      $form['submit'] = [
        '#type' => 'submit',
        '#value' => $this->t('Update account'),
      ];
    }
    else {
      $form['submit'] = [
        '#markup' => '<h2>' . $this->t('This form is only available to profiles which need an update.') . '</h2>',
      ];
    }
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    if (!filter_var($form_state->getValue(['mail']), FILTER_VALIDATE_EMAIL)) {
      $form_state->setErrorByName('mail', $this->t('You must specify a valid email address.'));
    }
    $existing = user_load_by_mail($form_state->getValue(['mail']));
    if ($existing) {
      $form_state->setErrorByName('mail', $this->t('This email address is already in use.'));
    }
    $pattern = \Drupal::config('ldap_authentication.settings')->get('emailTemplateUsagePromptRegex');
    $regex = '`' . $pattern . '`i';
    if (preg_match($regex, $form_state->getValue(['mail']))) {
      $form_state->setErrorByName('mail', $this->t('This email address still matches the invalid email template.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $proxy = \Drupal::currentUser();
    $user = User::load($proxy->id());
    $user->set('mail', $form_state->getValue('mail'));
    $user->save();
    drupal_set_message($this->t('Your profile has been updated.'));
    $form_state->setRedirect('<front>');
  }

}
