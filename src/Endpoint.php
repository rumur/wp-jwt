<?php

namespace Rumur\WordPress\JsonWebToken;

class Endpoint
{
    /**
     * Converts the endpoint into a regexp.
     *
     * @param string $endpoint The desired endpoint, can contain `*` e.g. 'wp/*\/posts'
     *
     * @return string as regexp |> `wp/*\/posts` -> '#wp\/(\w|\W)+/posts#
     * @internal
     *
     */
    public static function endpointAsRegExp(string $endpoint): string
    {
        return sprintf('#%s#', str_replace([ '*', '/' ], [ '(\w|\W)+', '\/' ], $endpoint));
    }

    /**
     * Prepares an endpoint for matching.
     *
     * @param string|array<string,callable>|\Closure $endpoint The endpoint that needs to be resolved.
     *
     * @return array<string, callable>
     * @see Endpoint::match()
     *
     */
    public static function prepare($endpoint): array
    {
        $prepared = null;

        // An endpoint could be just a closure or any callable,
        // so we're just giving it a wildcard to do the check by itself all endpoints.
        if (is_callable($endpoint)) {
            $prepared = [ static::endpointAsRegExp('*'), $endpoint ];
        }

        // An endpoint could be also an array where key as a string and value is a custom callable matcher.
        if (! $prepared && is_array($endpoint) && is_callable(current($endpoint))) {
            $prepared = [
                static::endpointAsRegExp(key($endpoint)),
                current($endpoint)
            ];
        }

        // An endpoint could be a string that just an uri of some endpoint.
        // In this case just add a default endpoint matcher.
        if (! $prepared && ! is_array($endpoint)) {
            $prepared = [
                static::endpointAsRegExp($endpoint),
                fn($regexp, $uri) => (bool) preg_match($regexp, $uri)
            ];
        }

        return $prepared;
    }

    /**
     * Checks whether an endpoint matches against one of the rules.
     *
     * @param string $uri The URI we need to match against.
     * @param array $rules The collection of rules that URI needs to be matched against.
     *
     * @return bool
     */
    public static function match(string $uri, array $rules): bool
    {
        $has_match = false;

        foreach ($rules as $regexp => $matcher) {
            // Bail out on a first match.
            if ($has_match) {
                break;
            }
            $has_match = (bool) $matcher($regexp, $uri);
        }

        return $has_match;
    }
}
