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
     * Holds the list of endpoint middlewares.
     *
     * @var array<string,callable>
     */
    protected array $middlewares = [];

    /**
     * Sets middleware for endpoints.
     *
     * @param array<string,string>|array<string,callable> $endpoints The list of endpoints that needs to be passed
     *                                                               through middleware.
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

                    $attributes = array_filter(explode(',', $attributes));

                    switch ($name) {
                        case 'role':
                            $middleware = Middleware\RoleMiddleware::class;
                            break;
                        case 'can':
                            $middleware = Middleware\UserCanMiddleware::class;

                            // UserCanMiddleware expects first param as user capability string
                            // and second traversable arguments.
                            $capability = $attributes[0];
                            unset($attributes[0]);

                            $attributes = [ $capability, $attributes ];
                            break;
                    }
                }

                if (is_callable($_middleware)) {
                    $middleware = $_middleware;
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

    public function shouldBeIgnored(string $endpoint): bool
    {
        return Endpoint::match($endpoint, $this->ignored());
    }

    public function middlewaresFor(string $endpoint): array
    {
        // Filter out all middlewares, so we get only ones for current endpoint.
        $matched = array_filter(
            $this->middlewares,
            fn($middlewares, $regexp) => Endpoint::match(
                $endpoint,
                [ $regexp => $middlewares['matcher'] ]
            ),
            ARRAY_FILTER_USE_BOTH
        );

        if (empty($matched)) {
            return [];
        }

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
        return array_reduce(
            wp_list_pluck($matched, 'middlewares'),
            static fn($collection, $middlewares) => array_merge($collection, (array) $middlewares),
            []
        );
    }

    public function applyFor($request, array $middlewares)
    {
        return ( new Middleware\Pipeline() )->send($request)->through($middlewares);
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
            if ($this->shouldBeIgnored($request->get_route())) {
                return $result;
            }

            $middlewares = $this->middlewaresFor($request->get_route());

            if (! empty($middlewares)) {
                $outcome = $this->applyFor($request, $middlewares);

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

                // We applied for a request, so we should get same request back,
                // if not sending back what we've got.
                if ($outcome !== $request) {
                    return $outcome;
                }
            }

            return $result;
        }, 20, 3);
    }
}
