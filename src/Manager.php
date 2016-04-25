<?php

namespace Logikos\Auth;

use Phalcon\Config;
use Phalcon\Exception;
use Phalcon\DiInterface;
use Phalcon\Security;
use Phalcon\Mvc\User\Component;
use Phalcon\Events\EventsAwareInterface;
use Phalcon\Session\AdapterInterface AS SessionAdapter;

class Manager extends Component implements EventsAwareInterface {
  
  /**
   * @var \Phalcon\Config
   */
  protected $authconf;
  
  /**
   * @var \Phalcon\Session\AdapterInterface
   */
  protected $session;
  
  /**
   * @var \Phalcon\Security
   */
  protected $security;
  
  public function __construct($userModelName) {
    //$this->_verifyConfig($config);
    $this->_verifyPhalconDiServices();
  }
  
  protected function _fireEvent($eventType,$data=null) {
    if ($this->getEventsManager() instanceof \Phalcon\Events\ManagerInterface) {
      return $this->getEventsManager()->fire($eventType,$this,$data);
    }
  }
  protected function _verifyConfig($config) {
    if (!($config instanceof \Phalcon\Config))
      throw new Exception('Config should be an instance of Phalcon\Config');
    
    
    $this->authconf = $config;
  }
  protected function _veryfyPhalconDiServices() {

    if (!($this->getDI() instanceof DiInterface))
      throw new Exception('To use please load Logikos\Auth\Manager as a Phalcon Di Service');
    
    if (!isset($this->session) || !($this->session instanceof SessionAdapter))
      throw new Exception('Please load a session manager in Phalcon\Di');
    
    if (!isset($this->security) || !($this->security instanceof Security))
      throw new Exception('Please load a security manager in Phalcon\Di');
    
  }
}