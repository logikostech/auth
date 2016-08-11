<?php
namespace Logikos\Auth;

use Logikos\Auth\Manager as AuthManager;
use Phalcon\Session\AdapterInterface AS SessionAdapter;
use Phalcon\Config;
use Phalcon\Phalcon;

class Session {
  /**
   * @var SessionAdapter
   */
  protected $session;
  
  /**
   * @var AuthManager
   */
  protected $auth;
  
  const KEY              = 'ltauth';
  const INDEX_USERID     = 'id';
  const INDEX_USERNAME   = 'name';
  const INDEX_LOGINTIME  = 'time';
  const INDEX_LASTACTIVE = 'atime';
  const INDEX_REMOTEADDR = 'addr';
  const INDEX_USERAGENT  = 'agent';
  const INDEX_ISACTIVE   = 'active';
  
  
  # session/login status
  const STATUS_VALID        = 1;
  const STATUS_NOT_SET      = 0;
  const STATUS_EXPIRED      = -1;
  const STATUS_HIJACKED     = -2;
  const STATUS_INACTIVE     = -3;
  
  public function __construct(AuthManager $auth, SessionAdapter $session) {
    $this->auth    = $auth;
    $this->session = $session;
    $this->updateLastActive();
  }
  
  /**
   * @return \Phalcon\Config
   */
  public function getData() {
    return $this->session->get(self::KEY, new Config());
  }
  
  public function set($index, $value) {
    $data = $this->getData();
    $data[$index] = $value;
    $this->session->set(self::KEY, $data);
    return $this;
  }
  
  public function get($index, $defaultValue=null) {
    return $this->getData()->get($index, $defaultValue);
  }
  
  public function getSessionStatus() {
    if ($this->isEmpty()) {
      return self::STATUS_NOT_SET;
    }
    if ($this->isExpired()) {
      return self::STATUS_EXPIRED;
    }
    if (!$this->isActive()) {
      return self::STATUS_INACTIVE;
    }
    if ($this->isHijackAtempt()) {
      return self::STATUS_HIJACKED;
    }
    return self::STATUS_VALID;
  }
  
  public function create(UserModelInterface $user) {
    $data = [
        self::INDEX_USERID     => $user->getUserId(),
        self::INDEX_USERNAME   => $user->getUsername(),
        self::INDEX_LOGINTIME  => time(),
        self::INDEX_LASTACTIVE => time(),
        self::INDEX_REMOTEADDR => $this->auth->getServerAttr('REMOTE_ADDR'),
        self::INDEX_USERAGENT  => $this->auth->getServerAttr('HTTP_USER_AGENT'),
        self::INDEX_ISACTIVE   => true
    ];
    $this->session->set(self::KEY,new Config($data));
    return $this;
  }
  public function destroy() {
    $this->session->remove(self::KEY);
  }
  public function isEmpty() {
    return $this->getData()->count() === 0;
  }
  public function isActive() {
    return $this->get(self::INDEX_ISACTIVE,false);
  }
  public function isExpired() {
    if (!$this->isActive()) {
      return null;
    }
    $expiretime = $this->getLastActive() + $this->getSessionTimeout();
    return $expiretime < time();
  }
  public function isHijackAtempt() {
    if (!$this->isActive()) {
      return null;
    }
    return !$this->remoteAddrMatch() || !$this->userAgentMatch();
  }
  protected function remoteAddrMatch() {
    return $this->auth->getServerAttr('REMOTE_ADDR')     === $this->get(self::INDEX_REMOTEADDR);
  }
  protected function userAgentMatch() {
    return $this->auth->getServerAttr('HTTP_USER_AGENT') === $this->get(self::INDEX_USERAGENT);
  }

  public function getUserId() {
    return $this->get(self::INDEX_USERID);
  }
  public function getUsername() {
    return $this->get(self::INDEX_USERNAME);
  }
  public function getLastActive() {
    return $this->get(self::INDEX_LASTACTIVE, 0);
  }
  public function updateLastActive() {
    return $this->set(self::INDEX_LASTACTIVE, time());
  }
  public function setInactive() {
    return $this->set(self::INDEX_ISACTIVE, false);
  }
  public function setActive() {
    return $this->set(self::INDEX_ISACTIVE, true);
  }
  public function getSessionTimeout() {
    return $this->auth->getUserOption(AuthManager::ATTR_SESSION_TIMEOUT);
  }
  public function has($index) {
    return $this->session->has($index);
  }
}