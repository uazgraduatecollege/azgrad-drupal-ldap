<?php

namespace Drupal\ldap_servers\Form;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Entity\ContentEntityConfirmFormBase;
use Drupal\Core\Url;

/**
 *
 */
class LdapServersAdminEnableDisable extends ContentEntityConfirmFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'ldap_servers_admin_enable_disable';
  }

  /**
   * {@inheritdoc}
   */
  public function getQuestion() {
    return $this->t('Are you sure you want to disable/enable entity %name?', array('%name' => $this->entity->label()));
  }

  /**
   * {@inheritdoc}
   *
   * If the delete command is canceled, return to the lti_tool_provider_consumer list.
   */
  public function getCancelURL() {
    return new Url('ldap_servers.settings');
  }

  /**
   * {@inheritdoc}
   */
  public function getConfirmText() {
    return $this->t('Disable/Enable');
  }

  /**
   *
   */
  public function buildForm(array $form, FormStateInterface $form_state, $action = NULL, $sid = NULL) {

    if ($ldap_server = ldap_servers_get_servers($sid, 'all', TRUE)) {
      $variables = [
        'ldap_server' => $ldap_server,
        'actions' => FALSE,
        'type' => 'detail',
      ];
      // @FIXME
      // theme() has been renamed to _theme() and should NEVER be called directly.
      // Calling _theme() directly can alter the expected output and potentially
      // introduce security issues (see https://www.drupal.org/node/2195739). You
      // should use renderable arrays instead.
      //
      //
      // @see https://www.drupal.org/node/2195739
      // $form['#prefix'] = "<div>" . theme('ldap_servers_server', $variables) . "</div>";
      // var_dump($ldap_server);die();
      $form['sid'] = [
        '#type' => 'hidden',
        '#value' => $sid,
      ];
      $form['name'] = [
        '#type' => 'hidden',
        '#value' => $ldap_server->name,
      ];
      $form['action'] = [
        '#type' => 'hidden',
        '#value' => $action,
      ];
      // Return $form;.
      return parent::buildForm($form, $form_state);

      // Return confirm_form($form, t('Are you sure you want to') . t($action) . ' ' . t('the LDAP server named <em><strong>%name</strong></em>?', [
      //   '%name' => $ldap_server->name
      //   ]), LDAP_SERVERS_MENU_BASE_PATH . '/servers/list', t('<p></p>'), t($action), t('Cancel'));.
    }

  }

  /**
   *
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    $name = $values['name'];
    $sid = $values['sid'];
    $status = ($values['action'] == 'enable') ? 1 : 0;

    if ($values['confirm'] && $sid) {

      $form_state->set(['redirect'], LDAP_SERVERS_MENU_BASE_PATH . '/servers');
      //FIXME: Incomplete port
      $ldap_server = new LdapServerAdmin($sid);

      $ldap_server->status = $status;
      $ldap_server->save('edit');
      $tokens = [
        '%name' => $values['name'],
        '%sid' => $sid,
        '%action' => t($values['action']) . 'd',
      ];
      drupal_set_message(t('LDAP Server Configuration %name (server id = %sid) has been !action.', $tokens));
      $message = t('LDAP Server !action: %name (sid = %sid) ', $tokens);
      \Drupal::logger('ldap')->notice($message, []);

    }

    drupal_set_message(t('Sid: ' . $sid));
    drupal_set_message(t('Name: ' . $name));
    drupal_set_message(t('Status: ' . $status));

    $form_state->setRedirect('entity.ldap_server.collection');
  }

}
