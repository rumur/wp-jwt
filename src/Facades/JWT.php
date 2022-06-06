<?php

namespace Facades;

use Illuminate\Support\Facades\Facade;
use Rumur\WordPress\JsonWebToken\Service;

/**
 * Class Notice
 *
 * @package Rumur\WordPress\JsonWebToken
 *
 * @method static Service guard(string|string[]$endpoints)
 * @method static Service ignore(string|string[] $endpoints)
 * @method static Service middleware(string|string[] $endpoints)
 * @method static Service takeOver(\Closure $routeResolver)
 * @method static void engage(string $namespace = 'jwt/v1', string $rest_base = 'auth')
 * @method static \stdClass validate(?string $token = null)
 * @method static bool invalidate(?string $token = null)
 * @method static string retrieveToken()
 * @method static \stdClass validateToken()
 * @method static array issueByCredentials()
 * @method static array issueFor(int|string|\WP_User $user)
 */
class JWT extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'rumur_wp_jwt';
    }
}
