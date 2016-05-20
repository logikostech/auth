<?php

namespace Logikos\Auth;

use Phalcon\Config;
use Phalcon\Exception;
use Phalcon\DiInterface;
use Phalcon\Security;
use Phalcon\Mvc\User\Component;
use Phalcon\Events\EventsAwareInterface;
use Phalcon\Session\AdapterInterface AS SessionAdapter;

class Manager extends Component {
  
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
  
  protected $_usermodelinterface = 'Logikos\Auth\UserModelInterface';
  
  public function __construct($userModelName) {
    if (!is_string($userModelName) || !class_exists($userModelName))
      throw new Exception('Constructor requires a user model name');
    
    if (!is_subclass_of($userModelName,$this->_usermodelinterface))
      throw new \Phalcon\Mvc\Model\Exception("Model {$userModelName} must implement {$this->_usermodelinterface}");
    
    //$this->_verifyConfig($config);
    $this->_verifyPhalconDiServices();
  }
  
  protected function _fireEvent($eventType,$data=null) {
    if ($this->getEventsManager() instanceof \Phalcon\Events\ManagerInterface) {
      return $this->getEventsManager()->fire($eventType,$this,$data);
    }
  }
  
  protected function _verifyPhalconDiServices()  {

    if (!($this->getDI() instanceof DiInterface))
      throw new Exception('To use please load Logikos\Auth\Manager as a Phalcon Di Service');
    
    if (!isset($this->session) || !($this->session instanceof SessionAdapter))
      throw new Exception('Please load a session manager in Phalcon\Di');
    
    if (!isset($this->security) || !($this->security instanceof Security))
      throw new Exception('Please load a security manager in Phalcon\Di');
    
  }
}