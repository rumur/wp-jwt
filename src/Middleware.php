<?php

namespace Rumur\WordPress\JsonWebToken;

class Middleware
{
    /**
     * Holds the list of endpoints that needs to be ignored by Middleware.
     *
     * @var array<string,callable>
     */
    protected array $ignore = [];

    /**
     * Holds the list of endpoints that needs to be guarded by JWT.
     *
     * @var array<string,callable>
     */
    protected array $guards = [];

    /**
     * Holds the list of endpoint middlewares.
     *
     * @var array<string,callable>
     */
    protected array $middlewares = [];

    /**
     * Sets middleware for endpoints.
     *
     * @param array<string,string>|array<string,callable> $endpoints The list of endpoints that needs to be passed through middleware.
     *
     * @return $this for chaining purpose.
     */
    public function add(array $endpoints): self
    {
        foreach ($endpoints as $raw_endpoint => $collection) {
            [ $endpoint, $matcher ] = Endpoint::prepare($raw_endpoint);

            $attributes  = [];
            $middlewares = [];

            foreach ((array) $collection as $_middleware) {
                // Fallback middleware
                $middleware = static fn($request) => $request;

                if (is_string($_middleware) && ! class_exists($_middleware)) {
                    [ $name, $attributes ] = array_pad(
                        explode(':', $_middleware, 2),
                        2,
                        ''
                    );

                    $attributes = explode(',', $attributes);

                    switch ($name) {
                        case 'role':
                            $middleware = Middleware\RoleMiddleware::class;

                            // Cleans up the empty string, if role list been forgotten.
                            $attributes = array_filter($attributes);
                            break;
                        case 'can':
                            $middleware = Middleware\UserCanMiddleware::class;

                            // UserCanMiddleware expects first param as user capability string
                            // and second traversable arguments.
                            $capability = $attributes[0];
                            unset($attributes[0]);

                            $attributes = [ $capability, array_filter($attributes) ];
                            break;
                    }
                }

                $middlewares[] = [ $middleware, $attributes ];
            }

            $this->middlewares[ $endpoint ] = [
                'matcher'     => $matcher,
                'middlewares' => $middlewares
            ];
        }

        return $this;
    }

    /**
     * Sets guarded endpoints.
     *
     * @param string|string[]|array<string,callable> $endpoints The list of endpoints that needs to be guarded by JWT.
     *
     * @return $this for chaining purpose.
     */
    public function guard($endpoints): self
    {
        foreach ((array) $endpoints as $raw_endpoint) {
            [ $endpoint, $resolver ] = Endpoint::prepare($raw_endpoint);

            $this->guards[ $endpoint ] = $resolver;
        }

        return $this;
    }

    public function guarded(): array
    {
        return $this->guards;
    }

    /**
     * Sets ignored endpoints.
     *
     * @param string|string[]|array<string,callable> $endpoints The list of endpoints that needs to be ignored by JWT.
     *
     * @return $this for chaining purpose.
     */
    public function ignore($endpoints): self
    {
        foreach ((array) $endpoints as $raw_endpoint) {
            [ $endpoint, $resolver ] = Endpoint::prepare($raw_endpoint);

            $this->ignore[ $endpoint ] = $resolver;
        }

        return $this;
    }

    /**
     * The list of the routes that need to be ignored.
     *
     * @return callable[]
     */
    public function ignored(): array
    {
        return $this->ignore;
    }

    /**
     * Registers all necessary hooks and filters.
     *
     * @return void
     */
    public function engage(): void
    {
        /**
         * Filters the pre-calculated result of a REST API dispatch request.
         *
         * Allow hijacking the request before dispatching by returning a non-empty. The returned value
         * will be used to serve the request instead.
         *
         * @param mixed           $result  Response to replace the requested version with. Can be anything
         *                                 a normal endpoint can return, or null to not hijack the request.
         * @param \WP_REST_Server  $server  Server instance.
         * @param \WP_REST_Request $request Request used to generate the response.
         */
        add_filter('rest_pre_dispatch', function ($result, \WP_REST_Server $server, \WP_REST_Request $request) {
            // Allow all other errors to bubble up first.
            if (is_wp_error($result)) {
                return $result;
            }

            // The endpoint should be ignored, bail out.
            if (Endpoint::match($request->get_route(), $this->ignore)) {
                return $result;
            }

            // Filter out all middlewares, so we get only ones for current endpoint.
            $route_middlewares = array_filter(
                $this->middlewares,
                fn($middlewares, $regexp) => Endpoint::match(
                    $request->get_route(),
                    [ $regexp => $middlewares['matcher'] ]
                ),
                ARRAY_FILTER_USE_BOTH
            );

            if (! empty($route_middlewares)) {
                /**
                 * Flatten all middlewares into one flat collection.
                 * Got: [
                 *      '#\/wp\/(?:\w|\W)+\/posts\/?$# => [
                 *          'matcher' => \Closure,
                 *          'middlewares' => [
                 *              [FirstMiddleware::class, 'handle'],
                 *              \Closure,
                 *              ...
                 *          ],
                 *          ...
                 *      ],
                 *      '#\/wp\/(?:\w|\W)+\/media\/?$# => [
                 *          'matcher' => \Closure,
                 *          'middlewares' => [
                 *              [SecondMiddleware::class, 'handle'],
                 *              \Closure,
                 *              ...
                 *          ],
                 *          ...
                 *      ],
                 *      ...
                 * ]
                 * Flattens into
                 * [
                 *      [FirstMiddleware::class, 'handle'],
                 *      \Closure,
                 *      // ...,
                 *      [SecondMiddleware::class, 'handle'],
                 *      \Closure,
                 *      // ...,
                 * ]
                 */
                $middlewares = array_reduce(
                    wp_list_pluck($route_middlewares, 'middlewares'),
                    static fn($collection, $pipes) => array_merge($collection, (array) $pipes),
                    []
                );

                $outcome = ( new Pipeline() )->send($request)->through($middlewares);

                if (is_wp_error($outcome)) {
                    return $outcome;
                }

                if (false === $outcome) {
                    return new \WP_Error(
                        'rest_authorization',
                        __('Sorry, You are not allowed to do that', 'rumur-jwt'),
                        [
                            'status' => rest_authorization_required_code()
                        ]
                    );
                }

                // We send a request, so we should get same request,
                // if not sending back what we got.
                if ($outcome !== $request) {
                    return $outcome;
                }
            }

            return $result;
        }, 20, 3);
    }
}
