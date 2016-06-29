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
  
  const ATTR_ENTITY          = 10;
  const ATTR_EMAIL_REQUIRED  = 20;
  const ATTR_PASS_SYMBOLS    = 100;
  const ATTR_PASS_MIN_LEN    = 110;
  const ATTR_PASS_MIN_LOWER  = 111;
  const ATTR_PASS_MIN_UPPER  = 112;
  const ATTR_PASS_MIN_NUMBER = 113;
  const ATTR_PASS_MIN_SYMBOL = 114;
  
  // this should be readonly but class constants cant be arrays in php < 5.6
  public static $default_options = [
      self::ATTR_ENTITY          => null,
      self::ATTR_EMAIL_REQUIRED  => true,
      self::ATTR_PASS_MIN_LEN    => 8,
      self::ATTR_PASS_MIN_LOWER  => 1,
      self::ATTR_PASS_MIN_UPPER  => 1,
      self::ATTR_PASS_MIN_NUMBER => 1,
      self::ATTR_PASS_MIN_SYMBOL => 1,
      self::ATTR_PASS_SYMBOLS    => '!@#$%^&*()_+-=~`{[}]|\;:\'",<.>/?'
  ];
  
  public function __construct($options=null) {
    if (is_a($options,self::USER_MODEL_INTERFACE))
      $options = [self::ATTR_ENTITY=>$options];
    
    $this->_setDefaultUserOptions(self::$default_options);
    
    if (is_array($options))
      $this->mergeUserOptions($options);
  }
  public function getEntity() {
    static $cache = [];
    $entity = $this->getUserOption(self::ATTR_ENTITY);
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
    $this->userExistsCheck($username, $email);
    $this->securePasswordCheck($password);
    $this->emailCheck($email);
    $user = $this->newEntity();
    $user->setUsername($username);
    $user->setPassword($this->getSecurity()->hash($password));
    $user->addEmail($email);
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
  public function emailCheck($email) {
    if ($this->getUserOption(self::ATTR_EMAIL_REQUIRED) && empty($email))
      throw new Exception('Email address is required');

    if (!is_null($email) && !filter_var($email, FILTER_VALIDATE_EMAIL))
      throw new Exception('Email address is invalid');
  }
  public function userExistsCheck($username, $email=null) {
    $entity = $this->newEntity();
    if ($entity->lookupUserByUsername($username))
      throw new UsernameTakenException();
    
    if (!is_null($email) && $entity->lookupUserByEmail($email))
      throw new EmailInUseException();
  }
}