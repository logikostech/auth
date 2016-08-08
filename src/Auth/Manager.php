<?php

namespace Logikos\Auth;

use Logikos\Auth\Session as AuthSession;
use Logikos\Auth\UserModelInterface;
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
   * @var AuthSession
   */
  protected $session;
  
  /**
   * @var \Phalcon\Security
   */
  protected $security;
  
  protected $tokenElement;
    
  # attributes - aparently to be used in Phalcon\Validation\Validator::setOption() these have to be strings ...
  const ATTR_ENTITY          = 'A10';
  const ATTR_EMAIL_REQUIRED  = 'A20';
  const ATTR_PASS_SYMBOLS    = 'A100';
  const ATTR_PASS_MIN_LEN    = 'A110';
  const ATTR_PASS_MIN_LOWER  = 'A111';
  const ATTR_PASS_MIN_UPPER  = 'A112';
  const ATTR_PASS_MIN_NUMBER = 'A113';
  const ATTR_PASS_MIN_SYMBOL = 'A114';
  const ATTR_SESSION_TIMEOUT = 'A200'; // seconds inactive to trigger timeout
  const ATTR_WORKFACTOR      = 'A101'; // int 4-32, higher numbers increase the time it takes to create and check password hashes, longer check times makes password cracking shower/harder
  
  # session/login status
  const SESSION_VALID        = 1;
  const SESSION_NOT_SET      = 0;
  const SESSION_EXPIRED      = -1;
  const SESSION_HIJACKED     = -2;
  const SESSION_INACTIVE     = -3;
  
  
  public final function __construct($options=null) {
    if ($options instanceof UserModelInterface) {
      $options = [self::ATTR_ENTITY=>$options];
    }
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
        self::ATTR_SESSION_TIMEOUT => (24*60*60), // seconds inactive to trigger timeout
        self::ATTR_WORKFACTOR      => 8
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
        if ($rc->implementsInterface(UserModelInterface::class)) {
          $cache[$entity] = true;
        }
      }
    }
    if ($cache[$entity] === false) {
      throw new InvalidEntityException('Constructor requires '.UserModelInterface::class);
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
   * @return UserModelInterface
   */
  public function getUserEntity() {
    if (!$this->getSession()->isEmpty()) {
      return $this->newEntity()->getUserById($this->getSession()->getUserId());
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
    $this->setPassword($user, $password);
    $user->addEmail($email);
    $user->save();
  }
  
  public function setPassword(UserModelInterface $user, $password) {
    $user->setPassword($this->getPasswordHash($password));
  }
  
  protected function getPasswordHash($password) {
    return $this->getSecurity()->hash(
        $password,
        $this->getUserOption(self::ATTR_WORKFACTOR)
    );
  }
  /**
   * 
   * @param string $login used to lookup user account in entity, perhaps username or email?
   * @param string $password
   */
  public function login($login, $password) {
    $user             = $this->getUserByLogin($login);
    
    if (!$user instanceof UserModelInterface) {
      // To protect against timing attacks. The script will take roughly the same amount of time.
      $this->getPasswordHash(rand());
      throw new Exception('No such user');
    }
    
    if (!$this->isCorrectPassword($user, $password)) {
      throw new Password\Exception();
    }
    if (!$this->isValidToken()) {
      throw new BadTokenException();
    }
    
    $this->getSession()->create($user);
  }
  public function logout() {
    $this->getSession()->destroy();
  }
  public function isCorrectPassword(UserModelInterface $user, $password) {
    return $this->getSecurity()->checkHash($password,$user->getPassword());
  }
  public function isValidToken() {
    return $this->getSecurity()->checkToken();
  }
  public function getServerAttr($attr) {
    static $cache;
    static $server;
    if (!$cache || $server !== $_SERVER) {
      $cache = new Config([
          'REMOTE_ADDR'     => 'localhost',
          'HTTP_USER_AGENT' => 'shell'
      ]);
      if ($_SERVER) {
        $cache->merge(new Config($_SERVER));
      }
    }
    $server = $_SERVER;
    return $cache[$attr];
  }
  public function isLoggedIn() {
    $status = $this->getLoginStatus();
    return $status > 0;
  }
  public function getLoginStatus() {
    if ($this->getSession()->isEmpty()) {
      return self::SESSION_NOT_SET;
    }
    if ($this->getSession()->isExpired()) {
      return self::SESSION_EXPIRED;
    }
    if (!$this->getSession()->isActive()) {
      return self::SESSION_INACTIVE;
    }
    if ($this->getSession()->isHijackAtempt()) {
      return self::SESSION_HIJACKED;
    }
    return self::SESSION_VALID;
  }

  public function getUserId() {
    return $this->getSession()->getUserId();
  }
  
  public function markSessionInactive() {
    $this->getSession()->setInactive();
  }

  public function getTokenElement($forcenew = false) {
    if ($forcenew || is_null($this->tokenElement) || !$this->getSession()->has('$PHALCON/CSRF/KEY$')) {
      $this->tokenkey = $this->getSecurity()->getTokenKey();
      $this->tokenval = $this->getSecurity()->getToken();
      
      $this->tokenElement = new Hidden($this->tokenkey);
      $this->tokenElement->setAttribute('value', $this->tokenval);
      $this->tokenElement->setAttribute('name', $this->tokenkey);
    }
    return $this->tokenElement;
  }
  
  public function renderTokenElement() {
    return $this->getTokenElement()->render();
  }
  
  /**
   * @throws Exception
   * @return AuthSession
   */
  public function getSession() {
    if (!$this->session) {      
      $session = $this->getDi()->get('session');
      if (!$session instanceof SessionAdapter) {
        throw new Exception('Please load a session manager in Phalcon\Di');
      }
      $this->session = new AuthSession($this, $session);
    }
    return $this->session;
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