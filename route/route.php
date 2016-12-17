<?php

	class Drupal8Plugin extends ZAppsPlugin {
		
		public function resolveMVCEnter($context) {
			
		}
		
		public function resolveMVCLeave($context) {
		
			if (!$this->resolved) {
				$request = $context['functionArgs'][0];

                $ctrl = $request->get('_controller');
                if (empty($ctrl) || (!is_array($ctrl) && !is_string($ctrl))) {
                        return;
                } elseif (is_string($ctrl)) {
                        $ctrl = explode(':', $ctrl);
                }
                $controller = $ctrl[0];
                if (!empty($ctrl[2])) {
                        $action = $ctrl[2];
                } else {
                        $action = $ctrl[1];
                }
                $this->setRequestMVC(array($controller, $action));
				$this->resolved = true;
			}			
		}		
		
		private $resolved = false;		
	}
	
	$drupalPlugin = new Drupal8Plugin();
	$drupalPlugin->setWatchedFunction("Symfony\Component\HttpKernel\HttpKernel::handle", array($drupalPlugin, "resolveMVCEnter"), array($drupalPlugin, "resolveMVCLeave"));
