<?php

namespace Logikos\Auth;

use Phalcon\Config;
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
   * @var Config
   */
  protected $authconf;
  
  /**
   * @var SessionAdapter
   */
  protected $session;
  
  /**
   * @var \Phalcon\Security
   */
  protected $security;
  
  const USER_MODEL_INTERFACE = 'Logikos\Auth\UserModelInterface';
  
  
  private $_defaultOptions = [
      'entity' => null,
      'minpass_length'    => 8,
      'minpass_lowercase' => 1,
      'minpass_uppercase' => 1,
      'minpass_numbers'   => 1,
      'minpass_symbols'   => 1,
      'valid_symbols'     => '!@#$%^&*()_+-=~`{[}]|\;:\'",<.>/?'
  ];
    
  public function __construct($options=null) {
    if (is_a($options,self::USER_MODEL_INTERFACE))
      $options = ['entity'=>$options];
    
    $this->_setDefaultUserOptions($this->_defaultOptions);
    
    if (is_array($options))
      $this->mergeUserOptions($options);
  }
  public function getEntity() {
    static $cache = [];
    $entity = $this->getUserOption('entity');
    if (!array_key_exists($entity,$cache)) {
      $cache[$entity] = false;
      if (!is_null($entity) && class_exists($entity)) {
        $rc = new \ReflectionClass($entity);
        if ($rc->implementsInterface(self::USER_MODEL_INTERFACE)) {
          $cache[$entity] = true;
        }
      }
    }
    if ($cache[$entity] === false) {
      throw new InvalidEntityException('Constructor requires '.self::USER_MODEL_INTERFACE);
    }
    return $entity;
  }
  /**
   * @return UserModelInterface
   */
  public function newEntity() {
    $entity = $this->getEntity();
    return new $entity;
  }
  /**
   * @param string $login
   * @return \Logikos\Auth\UserModleInterface
   */
  public function getUserByLogin($login) {
    return $this->newEntity()->getUserByLogin($login);
  }
  public function newUser($username, $password, $email=null) {
    $this->securePasswordCheck($password);
    $user = $this->newEntity();
    $user->setUsername($username);
    $user->setPassword($this->getSecurity()->hash($password));
    $user->save();
  }
  /**
   * 
   * @param string $login used to lookup user account in entity, perhaps username or email?
   * @param string $password
   */
  public function login($login, $password) {
    $user = $this->getUserByLogin($login);
    $passwordCheckPassed = $this->getSecurity()->checkHash($password,$user->getPassword());
    $tokenCheckPassed    = $this->getSecurity()->checkToken();
    
    if (!$passwordCheckPassed)
      throw new Password\Exception();
    
    if (!$tokenCheckPassed)
      throw new BadTokenException();
  }
  
  public function getTokenElement() {
    $this->tokenkey = $this->getSecurity()->getTokenKey();
    $this->tokenval = $this->getSecurity()->getToken();
    $mask = '<input type="hidden" name="%s" value="%s" />';
    return sprintf($mask, $this->tokenkey, $this->tokenval);
  }
  /**
   * @throws Exception
   * @return \Phalcon\Session
   */
  public function getSession() {
    static $session;
    if (!$session) {
      $session = $this->getDi()->get('session');
      if (!$session || !is_a($session,'Phalcon\Session\AdapterInterface'))
        throw new Exception('Please load a session manager in Phalcon\Di');
    }
    return $session;
  }
  /**
   * @throws Exception
   * @return \Phalcon\Security
   */
  public function getSecurity() {
    static $security;
    if (!$security) {
      $security = $this->getDi()->get('security');
      if (!$security || !is_a($security,'Phalcon\Security'))
        throw new Exception('Please load a security manager in Phalcon\Di');
    }
    return $security;
  }
  public function securePasswordCheck($password) {
    $pass = new Password($password,$this->getUserOptions());
    $pass->isSecure();
  }
}