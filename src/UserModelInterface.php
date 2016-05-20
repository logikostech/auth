<?php
namespace Logikos\Auth;

use Phalcon\Mvc\ModelInterface;

interface UserModelInterface extends ModelInterface {
  public static function getUsernameField();
  public static function getPasswordField();
}