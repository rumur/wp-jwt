# wp-jwt
WordPress JSON Web Token Authentication tool.

### Minimum Requirements:
 - PHP: 7.4+
 - WordPress: 5.9+

## Installation

```composer require rumur/wp-jwt```

### Themosis 2.x
```php console vendor:publish --provider='Rumur\WordPress\JsonWebToken\JWTServiceProvider'```

### Sage 10.x
```wp acorn vendor:publish --provider='Rumur\WordPress\JsonWebToken\JWTServiceProvider'```

### How to use it?

**Define Secret Key**

```php
// wp-config.php
// ...

define('JWT_SECRET_KEY', 'SomeSecretYouKey');

// Optional. Default `HS256`, Possible options `ES384`, `ES256`, `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `EdDSA`. 
define('JWT_ALGO', 'HS256');

/* That's all, stop editing! Happy blogging. */
// ...
```

```php

use function Rumur\WordPress\JsonWebToken\jwt;
use Rumur\WordPress\JsonWebToken\Service;

add_action('rest_api_init', function () {
    // Creates a Service for you. 
    jwt()
        // List routes that need to be guarded by JWT, support wildcards.
        ->guard( [ 
            'app/*',
            'wp/*/posts/*',
        ] )
        // In case if you need to skip some routes, otherwise you might get errors,
        // because absence of a Bearer Token within headers triggers that errors. 
        ->ignore( [
            'app/*/auth/login',
            'app/*/auth/validate',
            'app/*/auth/register',
        ] )
        // There is also available some builtin middlewares
        // but also supports simple closures as well,
        // ⚠️ NOTE: Middleware won't apply if that endpoint within ignore list ⚠️ 
        ->middleware( [
            'app/*/entity/*'  => [
                'role:editor',
                'can:edit_entity',
                function(\WP_REST_Request $request, Closure $next, array $attributes) {
                    // Do some logic.
                    // in case of success just pass the request to the next middleware
                    if (! current_user_can('edit_other_users')) {
                        return false;
                    }
                    
                    return $next($request);
                }
            ],
            'wp/*/media/*' => function(\WP_REST_Request $request, Closure $next, array $attributes) {
                if (! current_user_can('edit_post', $request['id'])) {
                    return false;
                }
               
                return $next($request);
            }
        ] )
        // In case if you need to take over the control and register your own routes.
        ->takeOver(function (string $namespace, string $rest_base, Service $jwt ) {
            ( new Api\AuthController($namespace, $rest_base, $jwt) )->register_routes();
        } )
        // And last but not least, Engage function needs to be called on `rest_api_init` action,
        // otherwise it will tell you about that error. 
        ->engage( $namespace = 'jwt/v1', $rest_base = 'auth' );
}, 10 );
```

## License
  This package is licensed under the MIT License - see the [LICENSE.md](https://github.com/rumur/wp-jwt/blob/master/LICENSE) file for details.
