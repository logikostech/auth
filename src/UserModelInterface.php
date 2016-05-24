<?php
namespace Logikos\Auth;

interface UserModelInterface {
  public function setUsername($username);
  public function setPassword($password);
  
  /**
   * @param string $username
   * @return Logikos\Auth\UserModelInterface
   */
  public function lookupByUsername($username);
  
  /**
   * @return Logikos\Auth\UserModelInterface
   */
  public function save();
  public function delete();
}