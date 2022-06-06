<?php

namespace Rumur\WordPress\JsonWebToken\Middleware;

/**
 * RoleMiddleware Class
 *
 * @package Rumur\WordPress\JsonWebToken
 */
class RoleMiddleware
{
    public function handle($request, $roles, $next)
    {
        $user = wp_get_current_user();

        // Seems somebody has forgotten to add attributes: role:editor,subscriber,...
        if ($user && empty($roles)) {
            return $next($request);
        }

        // So here we've got roles to check against.
        if ($user && ! empty(array_intersect($roles, $user->roles))) {
            return $next($request);
        }

        return false;
    }
}
