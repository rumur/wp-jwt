<?php
/*
Plugin Name:  WordPress JSON Web Token
Description:  WordPress JSON Web Token Authentication tool.
Version:      1.0.0
Author:       rumur
Author URI:   https://github.com/rumur
Text Domain:  rumur-jwt
PHP Version:  7.4
License:      MIT License
*/

/*
|--------------------------------------------------------------------------
| Register The Auto Loader
|--------------------------------------------------------------------------
|
| Composer provides a convenient, automatically generated class loader for
| the plugin. We will simply require it into the script here so that we
| don't have to worry about manually loading any of our classes later on.
|
*/

if (! file_exists($composer = __DIR__ . '/vendor/autoload.php')) {
    wp_die(__('Error locating autoloader. Please run <code>composer install</code>.', 'rumur-jwt'));
}

require $composer;
