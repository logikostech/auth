<?php

namespace Logikos\Auth;

use Logikos\Validation\Validator\PasswordStrength;
use Phalcon\Config;
use Phalcon\DiInterface;
use Phalcon\Events\EventsAwareInterface;
use Phalcon\Forms\Element\Hidden;
use Phalcon\Mvc\User\Component;
use Phalcon\Mvc\User\Module;
use Phalcon\Session\AdapterInterface AS SessionAdapter;
use Phalcon\Security;
use Phalcon\Validation;

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
  
  # attributes - aparently to be used in Phalcon\Validation\Validator::setOption() these have to be strings ...
  const ATTR_ENTITY          = 'A10';
  const ATTR_EMAIL_REQUIRED  = 'A20';
  const ATTR_PASS_SYMBOLS    = 'A100';
  const ATTR_PASS_MIN_LEN    = 'A110';
  const ATTR_PASS_MIN_LOWER  = 'A111';
  const ATTR_PASS_MIN_UPPER  = 'A112';
  const ATTR_PASS_MIN_NUMBER = 'A113';
  const ATTR_PASS_MIN_SYMBOL = 'A114';
  const ATTR_SESSION_TIMEOUT = 'A200';
  
  # session/login status
  const SESSION_VALID        = 1;
  const SESSION_NOT_SET      = 0;
  const SESSION_EXPIRED      = -1;
  const SESSION_HIJACKED     = -2;
  
  
  public final function __construct($options=null) {
    if (is_a($options,self::USER_MODEL_INTERFACE))
      $options = [self::ATTR_ENTITY=>$options];
    
    $this->_setDefaultUserOptions(self::defaultUserOptions());
    
    if (is_array($options))
      $this->mergeUserOptions($options);
    
    if (method_exists($this,"onConstruct")) {
      $this->{"onConstruct"}();
    }
  }
  
  public static function defaultUserOptions() {
    return [
        self::ATTR_ENTITY          => null,
        self::ATTR_EMAIL_REQUIRED  => true,
        self::ATTR_PASS_MIN_LEN    => 8,
        self::ATTR_PASS_MIN_LOWER  => 1,
        self::ATTR_PASS_MIN_UPPER  => 1,
        self::ATTR_PASS_MIN_NUMBER => 1,
        self::ATTR_PASS_MIN_SYMBOL => 1,
        self::ATTR_PASS_SYMBOLS    => '!@#$%^&*()_+-=~`{[}]|\\;:\'",<.>/?',
        self::ATTR_SESSION_TIMEOUT => 60 // seconds inactive to trigger timeout
    ];
  }
  /**
   * @throws InvalidEntityException
   * @return \Logikos\Auth\UserModelInterface
   */
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
  public function getUserEntity() {
    $sessionAuth = $this->getSessionAuth();
    if (!empty($sessionAuth['id'])) {
      return $this->newEntity()->getUserById($sessionAuth['id']);
    }
  }
  /**
   * @param string $login
   * @return \Logikos\Auth\UserModelInterface
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
    if (!is_a($user,self::USER_MODEL_INTERFACE)) {
      throw new Exception('No such user');
    }
    $passwordCheckPassed = $this->getSecurity()->checkHash($password,$user->getPassword());
    $tokenCheckPassed    = $this->getSecurity()->checkToken();
    
    if (!$passwordCheckPassed) {
      throw new Password\Exception();
    }
    if (!$tokenCheckPassed) {
      throw new BadTokenException();
    }
    
    $this->setSessionAuth([
        'id'     => $user->getUserId(),
        'name'   => $user->getUsername(),
        'time'   => time(), // time of signin
        'atime'  => time(), // time of last activity
        'addr'   => $this->serverAttr('REMOTE_ADDR'),
        'agent'  => $this->serverAttr('HTTP_USER_AGENT'),
        'active' => 1
    ]);
  }
  public function serverAttr($attr) {
    static $default = [
        'REMOTE_ADDR'     => 'localhost',
        'HTTP_USER_AGENT' => 'shell'
    ];
    return isset($_SERVER[$attr]) ? $_SERVER[$attr] : $default[$attr];
  }
  public function isLoggedIn() {
    $status = $this->getLoginStatus();
    return $status > 0;
  }
  public function updateLastActiveTime() {
    $auth = $this->requireSessionAuth();
    $auth['atime'] = time();
    $this->setSessionAuth($auth);
  }
  public function getLoginStatus() {
    $auth = $this->getSessionAuth();
    if (is_null($auth) || !is_array($auth))
      return self::SESSION_NOT_SET;
    
    if ($this->isExpired())
      return self::SESSION_EXPIRED;
    
    if ($this->isHijackAtempt())
      return self::SESSION_HIJACKED;
    
    $this->updateLastActiveTime();
    return self::SESSION_VALID;
  }

  protected function setSessionAuth($auth) {
    $this->getSession()->set('auth',$auth);
  }
  public function getSessionAuth() {
    return $this->getSession()->get('auth', null);
  }
  protected function requireSessionAuth() {
    $auth = $this->getSessionAuth();
    if (!is_array($auth)) {
      throw new Exception('Invalid Session');
    }
    return $auth;
  }
  public function isExpired() {
    $auth = $this->requireSessionAuth();
    $expiretime = $auth['time'] + $this->getUserOption(self::ATTR_SESSION_TIMEOUT);
    return $expiretime < time();
  }
  public function isHijackAtempt() {
    $auth = $this->requireSessionAuth();
    $addrMatch  = $this->serverAttr('REMOTE_ADDR')     === $auth['addr'];
    $agentMatch = $this->serverAttr('HTTP_USER_AGENT') === $auth['agent'];
    return !$addrMatch || !$agentMatch;
  }

  public function getTokenElement() {
    $this->tokenkey = $this->getSecurity()->getTokenKey();
    $this->tokenval = $this->getSecurity()->getToken();
    
    $element = new Hidden($this->tokenkey);
    $element->setAttribute('value', $this->tokenval);
    $element->setAttribute('name', $this->tokenkey);
    
    return $element;
    
//     $mask = '<input type="hidden" name="%s" value="%s" />';
//     return sprintf($mask, $this->tokenkey, $this->tokenval);
  }
  public function renderTokenElement() {
    return $this->getTokenElement()->render();
  }
  /**
   * @throws Exception
   * @return \Phalcon\Session\Adapter
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
    if (!$this->isPasswordSecure($password)) {
      throw new Password\StrengthException();
    }
  }
  public function isPasswordSecure($password) {
    $ps = new PasswordStrength($this->getUserOptions());
    $v  = new Validation([['password', $ps]]);
    $this->messages = $v->validate(['password'=>$password]);
    return count($this->messages) === 0;
  }
  public function emailCheck($email) {
    if ($this->getUserOption(self::ATTR_EMAIL_REQUIRED) && empty($email))
      throw new Exception('Email address is required');

    if (!is_null($email) && !filter_var($email, FILTER_VALIDATE_EMAIL))
      throw new Exception('Email address is invalid');
  }
  public function userExistsCheck($username, $email=null) {
    $entity = $this->newEntity();
    if ($entity->getUserByUsername($username))
      throw new UsernameTakenException();
    
    if (!is_null($email) && $entity->getUserByEmail($email))
      throw new EmailInUseException();
  }
}