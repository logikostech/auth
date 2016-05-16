<?php
namespace Logikos\Auth;

interface UserModelInterface {
  public static function getUsernameField();
  public static function getPasswordField();
}