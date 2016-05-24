<?php

namespace Logikos\Auth;

use Phalcon\Config;
use Phalcon\Exception;
use Phalcon\DiInterface;
use Phalcon\Security;
use Phalcon\Mvc\User\Component;
use Phalcon\Events\EventsAwareInterface;
use Phalcon\Session\AdapterInterface AS SessionAdapter;
use Phalcon\Mvc\User\Module;

class Manager extends Module {
  use \Logikos\UserOptionTrait;
  use \Logikos\Events\EventsAwareTrait;
  
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
  
  const USER_MODEL_INTERFACE = 'Logikos\Auth\UserModelInterface';
    
  public function __construct($options) {
    if (is_a($options,self::USER_MODEL_INTERFACE))
      $options = ['entity'=>$options];
    
    if (is_array($options))
      $this->mergeUserOptions($options);
    
    $this->_validateUserOptions();
  }
  public function getEntity() {
    return $this->getUserOption('entity');
  }
  
  protected function _validateUserOptions() {
    if (!is_a($this->getEntity(),self::USER_MODEL_INTERFACE))
      throw new InvalidEntityException('Constructor requires '.self::USER_MODEL_INTERFACE);
  }
  public function getSession() {
    static $session;
    if (!$session) {
      $session = $this->getDi()->get('session');
      if (!$session || !is_a($session,'Phalcon\Session\AdapterInterface'))
        throw new Exception('Please load a session manager in Phalcon\Di');
    }
    return $session;
  }
  public function getSecurity() {
    static $security;
    if (!$security) {
      $security = $this->getDi()->get('session');
      if (!$security || !is_a($security,'Phalcon\Security'))
        throw new Exception('Please load a security manager in Phalcon\Di');
    }
    return $security;
  }
}