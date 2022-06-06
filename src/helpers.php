<?php

namespace Rumur\WordPress\JsonWebToken;

/**
 * Helper factory function, to create JWT Service.
 *
 * @param string|null $secret Optional. Secret Key, default defined `JWT_SECRET` constant is used.
 * @param string|null $algo Optional. Default defined `JWT_ALGO` constant is used. Possible options `ES384`, `ES256`, `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `EdDSA`.
 *
 * @return Service
 */
function jwt(?string $secret = null, ?string $algo = 'HS256'): Service
{
    static $service;

    if (! $service) {
        $service = new Service($secret, $algo);
    }

    return $service;
}
