<?php
/**
 * WP config file used during the unit tests.
 * ⚠️ NOTE: wp-env will replace it with its own config file.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/tools/wp/' );

define( 'WP_DEFAULT_THEME', basename( dirname( __DIR__ ) ) );
define( 'WP_DEBUG', true );

define( 'DB_NAME', getenv( 'WP_DB_NAME' ) ?: 'wp_phpunit_tests' );
define( 'DB_USER', getenv( 'WP_DB_USER' ) ?: 'root' );
define( 'DB_PASSWORD', getenv( 'WP_DB_PASS' ) ?: '' );
define( 'DB_HOST', getenv( 'WP_DB_HOST' ) ?: 'localhost' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );

$table_prefix = 'wp_phpunit_tests_';

define( 'WP_TESTS_DOMAIN', 'example.dev' );
define( 'WP_TESTS_EMAIL', 'admin@example.dev' );
define( 'WP_TESTS_TITLE', 'Test Dev Instance' );

define( 'WP_PHP_BINARY', 'php' );

define( 'WPLANG', '' );
