<?php
/*********************************
 * Drupal 8 Z-Ray Extension
 **********************************/
namespace ZRay;

class Drupal8 {
  private $zre = NULL;

  public function setZRE($zre) {
    $this->zre = $zre;
  }

  public function eventDispatchExit($context, &$storage) {
    if (!$context['functionArgs'][1]) {
      return;
    }
    $event = $context['functionArgs'][1];
    $storage['events'][] = array(
      'name' => $event->getName(),
      'type' => get_class($event),
      'dispatcher' => get_class($event->getDispatcher()),
      'propagation stopped' => $event->isPropagationStopped(),
    );
  }

  public function registerBundlesExit($context, &$storage) {
    $bundles = $context['returnValue'];

    foreach ($bundles as $bundle) {
      $storage['bundles'][] = @array(
        'name' => $bundle->getName(),
        'namespace' => $bundle->getNamespace(),
        'container' => get_class($bundle->getContainerExtension()),
        'path' => $bundle->getPath(),
      );
    }
  }

  public function handleRequestExit($context, &$storage) {
    $request = $context['functionArgs'][0];

    if (empty($request)) {
      return;
    }
    $ctrl = $request->get('_controller');
    if (empty($ctrl)) {
      return;
    }
    if (empty($ctrl) || !(is_array($ctrl) || is_string($ctrl))) {
      return;
    }
    elseif (is_string($ctrl)) {
      $ctrl = explode(':', $ctrl);
    }
    $controller = $ctrl[0];
    if (!empty($ctrl[2])) {
      $action = $ctrl[2];
    }
    else {
      $action = $ctrl[1];
    }
    try {
      $refclass = new \ReflectionClass($controller);
      $filename = $refclass->getFileName();
      $lineno = $refclass->getStartLine();
    } catch (\Exception $e) {
      $filename = $lineno = '';
    }
    $storage['request'][] = @array(
      'Controller' => $controller,
      'Action' => $action,
      'Filename' => $filename,
      'Line Number' => $lineno,
      'Route' => array(
        'Name' => $request->get('_route'),
        'Object' => (array) $request->get('_route_object'),
      ),
      'Session' => ($request->getSession() ? 'yes' : 'no'),
      'Locale' => $request->getLocale(),
    );
  }

  public function terminateExit($context, &$storage) {
    $thisCtx = $context['this'];

    $listeners = $thisCtx->getContainer()
      ->get('event_dispatcher')
      ->getListeners();

    foreach ($listeners as $listenerName => $listener) {
      $listenerEntries = array();
      foreach ($listener as $callable) {
        switch (gettype($callable)) {
          case 'array':
            if (gettype($callable[0]) == 'string') {
              $strCallable = $callable[0] . '::' . $callable[1];
            }
            else {
              $strCallable = get_class($callable[0]) . '::' . $callable[1];
            }
            break;
          case 'string':
            $strCallable = $callable;
            break;
          case 'object':
            $strCallable = get_class($callable);
            break;
          default:
            $strCallable = 'unknown';
            break;
        }
        $listenerEntries[$listenerName][] = $strCallable;
      }
    }
    $storage['listeners'][] = $listenerEntries;
    $securityCtx = $thisCtx->getContainer()->get('security.context');
    $securityToken = ($securityCtx ? $securityCtx->getToken() : NULL);

    $isAuthenticated = FALSE;
    $authType = '';
    $attributes = array();
    $userId = '';
    $username = '';
    $salt = '';
    $password = '';
    $email = '';
    $isEnabled = '';
    $roles = array();
    $tokenClass = 'No security token available';

    if ($securityToken) {
      $attributes = $securityToken->getAttributes();
      $tokenClass = get_class($securityToken);

      $isAuthenticated = $securityToken->isAuthenticated();
      if ($isAuthenticated) {
        if ($securityCtx->isGranted('IS_AUTHENTICATED_FULLY')) {
          $authType = 'IS_AUTHENTICATED_FULLY';
        }
        else {
          if ($securityCtx->isGranted('IS_AUTHENTICATED_REMEMBERED')) {
            $authType = 'IS_AUTHENTICATED_REMEMBERED';
          }
          else {
            if ($securityCtx->isGranted('IS_AUTHENTICATED_ANONYMOUSLY')) {
              $authType = 'IS_AUTHENTICATED_ANONYMOUSLY';
            }
            else {
              $authType = 'Unknown';
            }
          }
        }
      }
      $user = $securityToken->getUser();
      if ($user) {
        if ($user !== 'anon.') {
          $userId = (method_exists($user, 'getId')) ? $user->getId() : '';
          $username = (method_exists($user, 'getUsername')) ? $user->getUsername() : '';
          $salt = (method_exists($user, 'getSalt')) ? $user->getSalt() : '';
          $password = (method_exists($user, 'getPassword')) ? $user->getPassword() : '';
          $email = (method_exists($user, 'getEmail')) ? $user->getEmail() : '';
          $isEnabled = (method_exists($user, 'isEnabled')) ? $user->isEnabled() : '';
          $roles = (method_exists($user, 'getRoles')) ? $user->getRoles() : '';
        }
        else {
          $username = 'anonymous';
        }
      }
    }

    $storage['security'][] = @array(
      'isAuthenticated' => $isAuthenticated,
      'username' => $username,
      'user id' => $userId,
      'roles' => $roles,
      'authType' => $authType,
      'isEnabled' => $isEnabled,
      'email' => $email,
      'attributes' => $attributes,
      'password' => $password,
      'salt' => $salt,
      'token type' => $tokenClass,
    );

  }

  public function logAddRecordExit($context, &$storage) {
    static $logCount = 0;

    $record = $context['locals']['record'];

    $storage['Monolog'][] = array(
      '#' => ++$logCount,
      'message' => $record['message'],
      'level' => $record['level_name'],
      'channel' => $record['channel'],
    );
  }

  public function callUserFuncExit($context, &$storage) {
    $called = $context['functionArgs'][0];
    $parameter = isset($context['functionArgs'][1]) ? $context['functionArgs'][1] : '';
    $blob = isset($context['functionArgs'][2]) ? json_encode($context['functionArgs'][2]) : '';

    if (!$this->is_closure($called) && !$this->is_closure($parameter) && !$this->is_closure($blob) && !is_array($called) && !is_object($called)) {
      $storage['CalledFunctions'][$called] = array(
        'called' => $called,
        'parameter' => $this->simplifyData($parameter),
        'info' => $this->simplifyData($blob),
      );
    }
  }

  public function callUserFuncArrayExit($context, &$storage) {
    $called = $context['functionArgs'][0];
    $parameter = $context['functionArgs'][1];

    if (!$this->is_closure($called) && !is_array($called) && !is_object($called)) {
      $storage['CalledFunctions'][$called] = array(
        'called' => $called,
        'parameter' => 'Array(' . sizeof($parameter) . ' items)',
        // $this->simplifyData($parameter, 0, 3),
      );
    }
  }

  private function is_closure($t) {
    return is_object($t) && ($t instanceof Closure);
  }

  public function blockViewBuilderPreRenderExit($context, &$storage) {
    $build = $context['functionArgs'][0];

    $build['#block'] = 'Array(' . sizeof($build['#block']) . ' items)';
    $storage['Blocks'][$build['#id']] = $this->simplifyData($build);
  }

  public function viewsPreRenderExit($context, &$storage) {
    $view = $context['functionArgs'][0];

    $storage['Views'][$view->storage->id()] = array(
      'view_name' => $view->storage->id(),
      'view_display_id' => $view->current_display,
      'view_args' => $view->args,
      'view_base_path' => $view->getPath(),
      'view_dom_id' => $view->dom_id,
      'pager_element' => isset($view->pager) ? $view->pager->getPagerId() : 0,
      //'View Object' => $this->simplifyData($view),
    );
  }

  public function drupalServiceExit($context, &$storage) {
    static $serviceIds = array();
    $id = $context['functionArgs'][0];
    if (empty($serviceIds[$id])) {
      $serviceIds[$id] = $id;
      $returnValue = $context['returnValue'];
      $storage['Services'][$id] = array(
        'ID' => $id,
        'Class' => !is_object($returnValue) ? $returnValue : get_class($returnValue),
      );
    }
  }

  public function moduleHandlerLoadExit($context, &$storage) {
    $name = $context['functionArgs'][0];
    $storage['Modules'][$name] = array(
      'Name' => $name,
    );
  }

  public function moduleHandlerInvokeExit($context, &$storage) {
    $module = $context['functionArgs'][0];
    $hook = $context['functionArgs'][1];
    if (empty($module) || empty($hook) || !function_exists($module . '_' . $hook)) {
      return;
    }

    $args = empty($context['functionArgs'][2]) ? NULL : $context['functionArgs'][2];
    $storage['Hooks'][$module . '_' . $hook] = array(
      'Module' => $module,
      'Hook' => $hook,
      'Function' => $module . '_' . $hook,
      // 'Args' => $this->simplifyData($args),
    );
  }

  private function simplifyData($data, $depth = 0, $maxDepth = 5) {
    $return = NULL;
    if (is_array($data) || is_object($data)) {
      foreach ($data as $key => $value) {
        if ($depth <= $maxDepth) {
          $return[$key] = $this->simplifyData($value, $depth + 1);
        }
        else {
          $return[$key] = 'N/A: Reached limit.';
        }
      }
    }
    else {
      $return = $data;
    }
    return $return;
  }

  public function logChannelLogExit($context, &$storage) {
    $logLevels = array(
      0 => 'EMERGENCY',
      1 => 'ALERT',
      2 => 'CRITICAL',
      3 => 'ERROR',
      4 => 'WARNING',
      5 => 'NOTICE',
      6 => 'INFO',
      7 => 'DEBUG',
    );

    $level = $context['functionArgs'][0];
    $message = $context['functionArgs'][1];
    if (empty($level) || empty($message)) {
      return;
    }

    $logContext = empty($context['functionArgs'][2]) ? NULL : $context['functionArgs'][2];
    $storage['Logs'][$logLevels[$level]] = array(
      'Message' => $message,
      'Context' => $logContext,
    );
  }

  public function formBuilderGetFormExit($context, &$storage) {
    $form = $context['returnValue'];

    $storage['Forms'][$form['#form_id']] = array(
      '#id' => $form['#id'],
      '#form_id' => $form['#form_id'],
      '#attributes' => $form['#attributes'],
      '#build_id' => $form['#build_id'],
      //'Form Structure' => $this->simplifyData($form),
    );
  }
}

$zre = new \ZRayExtension("drupal8");

$zrayDrupal = new Drupal8();
$zrayDrupal->setZRE($zre);

$zre->setMetadata(array(
  'logo' => __DIR__ . DIRECTORY_SEPARATOR . 'logo.png',
));

$zre->setEnabledAfter('Drupal\Core\DrupalKernel::handle');

//$zre->traceFunction("Symfony\Component\HttpKernel\Kernel::terminate", function(){}, array($zrayDrupal, 'terminateExit'));
$zre->traceFunction('Drupal\Core\DrupalKernel::handle', function () {}, array($zrayDrupal, 'handleRequestExit'));
$zre->traceFunction('Drupal\block\BlockViewBuilder::preRender', function () {}, array($zrayDrupal, 'blockViewBuilderPreRenderExit'));
$zre->traceFunction('views_views_pre_render', function () {}, array($zrayDrupal, 'viewsPreRenderExit'));
$zre->traceFunction('Drupal::service', function () {}, array($zrayDrupal, 'drupalServiceExit'));
$zre->traceFunction('Drupal\Core\Extension\ModuleHandler::load', function () {}, array($zrayDrupal, 'moduleHandlerLoadExit'));
$zre->traceFunction('Drupal\Core\Extension\ModuleHandler::invoke', function () {}, array($zrayDrupal, 'moduleHandlerInvokeExit'));
$zre->untraceFunction('Drupal\Core\Extension\ModuleHandler::invokeAll');
$zre->traceFunction('Drupal\dblog\Logger\DbLog::log', function () {}, array($zrayDrupal, 'logChannelLogExit'));
$zre->traceFunction('Drupal\Core\Form\FormBuilder::getForm', function () {}, array($zrayDrupal, 'formBuilderGetFormExit'));
//$zre->traceFunction("Symfony\Component\EventDispatcher\EventDispatcher::dispatch", function(){}, array($zrayDrupal, 'eventDispatchExit'));
//$zre->traceFunction("AppKernel::registerBundles", function(){}, array($zrayDrupal, 'registerBundlesExit'));
$zre->traceFunction("call_user_func", function () {}, array($zrayDrupal, 'callUserFuncExit'));
$zre->traceFunction("call_user_func_array", function () {}, array($zrayDrupal, 'callUserFuncArrayExit'));
