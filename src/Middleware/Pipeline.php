<?php

namespace Rumur\WordPress\JsonWebToken;

/**
 * Pipeline Class
 *
 * @package Rumur\WordPress\JsonWebToken
 */
class Pipeline
{
    /**
     * The Passable payload being passed through pipes.
     *
     * @var mixed
     */
    protected $payload;

    /**
     * The collection of pipes.
     *
     * @var callable
     */
    protected $pipes = [];

    /**
     * The method that is going to be called on every pipe if it's an instance of an object.
     *
     * @var string
     */
    protected string $method = 'handle';

    /**
     * Sets the payload that needs to be passed via some pipes.
     *
     * @param mixed $payload Anything that needs to passed over all pipes.
     * @return self Self instance.
     */
    public function send($payload): Pipeline
    {
        $this->payload = $payload;

        return $this;
    }

    /**
     * The method that is gonna be called on pipes.
     *
     * @param string $method The name of desired method.
     * @return self Self instance.
     */
    public function via(string $method): Pipeline
    {
        $this->method = $method;

        return $this;
    }

    /**
     * Sets the pipes and passes the payload through them.
     *
     * @param callable[] $middlewares The collection of middlewares.
     *
     * @return mixed    The result of pipeline.
     */
    public function through(array $middlewares)
    {
        $pipeline = array_reduce(
            array_reverse($middlewares),
            function ($next, $pipe) {

                [ $middleware, $attributes ] = $pipe;

                return function ($payload) use ($middleware, $attributes, $next) {
                    // Resolve if class wasn't instantiated.
                    if (is_string($middleware) && class_exists($middleware)) {
                        $middleware = new $middleware();
                    }

                    // Make a callable instance in case if class doesn't have `__invoke` method,
                    // we substitute it with predefined method.
                    if (is_object($middleware) && ! is_callable($middleware)) {
                        $middleware = [ $middleware, $this->method ];
                    }

                    // TODO: Add a reflection check if the handler needs `$attributes`
                    return $middleware($payload, $attributes, $next);
                };
            },
            static fn($payload) => $payload,
        );

        return $pipeline($this->payload);
    }
}
