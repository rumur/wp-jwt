<?php

namespace Rumur\WordPress\JsonWebToken\Middleware;

/**
 * UserCanMiddleware Class
 *
 * @package Rumur\WordPress\JsonWebToken
 */
class UserCanMiddleware
{
    public function handle($request, $attributes, $next)
    {
        [ $capability, $args ] = $attributes;

        if (current_user_can($capability, ...$args)) {
            return $next($request);
        }

        return false;
    }
}
