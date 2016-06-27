<?php
$basedir  = realpath(__DIR__.'/..');
$composer = $basedir . "/vendor/autoload.php";
if (file_exists($composer))
  include_once $composer;

$loader = new \Phalcon\Loader;
$loader
  ->registerNamespaces([
    'Logikos/Auth' => $basedir.'/src'
  ])
  ->register();

use Phalcon\Di\FactoryDefault as Di;

$di = new Di();

$di->set('auth',"Logikos\\Auth\\Manager",true);

Phalcon\DI::setDefault($di);