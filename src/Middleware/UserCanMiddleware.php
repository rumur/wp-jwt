<?php

namespace Rumur\WordPress\JsonWebToken\Middleware;

use Closure;
use WP_REST_Request;

/**
 * UserCanMiddleware Class
 *
 * @package Rumur\WordPress\JsonWebToken
 */
class UserCanMiddleware
{
    public function handle(WP_REST_Request $request, Closure $next, array $attributes)
    {
        [ $capability, $args ] = $attributes;

        if (current_user_can($capability, ...$args)) {
            return $next($request);
        }

        return false;
    }
}
