<?php

namespace Rumur\WordPress\JsonWebToken;

class Service
{
    /**
     * Holds the error during user resolver.
     *
     * @var ?\WP_Error
     */
    protected ?\WP_Error $user_resolver_error = null;

    /**
     * The Developers' own RestAPI routes register function.
     *
     * @var \Closure|null
     */
    protected ?\Closure $routeResolver = null;

    /**
     * Instance of an Issuer of tokens.
     *
     * @var Issuer
     */
    protected Issuer $issuer;

    /**
     * Instance of a Middleware.
     *
     * @var Middleware
     */
    protected Middleware $middleware;

    /**
     * Instantiate a Service.
     *
     * @param string|null $secret  Secret Key.
     * @param string|null $algo    Optional. Possible options `ES384`, `ES256`, `HS256`, `HS384`,
     *                             `HS512`, `RS256`, `RS384`, `RS512`, `EdDSA`.
     */
    public function __construct(?string $secret = null, ?string $algo = 'HS256')
    {
        $this->issuer = new Issuer(
            $secret ?? ( defined('JWT_SECRET') ? JWT_SECRET : false ),
            $algo ?? ( defined('JWT_ALGO') ? JWT_ALGO : false )
        );

        $this->middleware = new Middleware();
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
        $this->middleware->guard($endpoints);

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
        $this->middleware->ignore($endpoints);

        return $this;
    }

    /**
     * Sets middleware for endpoints.
     *
     * @param string|string[]|array<string,callable> $endpoints The list of endpoints that needs to be passed
     *                                                          through middleware.
     *
     * @return $this for chaining purpose.
     */
    public function middleware($endpoints): self
    {
        $this->middleware->add($endpoints);

        return $this;
    }

    /**
     * Registers all necessary hooks and filters.
     *
     * @param string $namespace
     * @param string $rest_base
     *
     * @return void
     */
    public function engage(string $namespace = 'jwt/v2', string $rest_base = 'auth'): void
    {
        if ('rest_api_init' !== current_action()) {
            $message = __('Service should be engaged on `rest_api_init` hook action.', 'rumur-jwt');

            _doing_it_wrong(__CLASS__, $message, '1.0.0');

            throw new \RuntimeException($message);
        }

        $this->registerRoutes($namespace, $rest_base);
        $this->registerUserResolver();
        $this->registerMiddlewares();
    }

    /**
     * When Developers decided to take a control over registering rest routes.
     *
     * @param \Closure $routeResolver
     *
     * @return $this
     */
    public function takeOver(\Closure $routeResolver): self
    {
        $this->routeResolver = $routeResolver;

        return $this;
    }

    /**
     * Checks whether the token decodes correctly and passes all checks.
     * In case if the Token was not provided it will try to retrieve the token from Authorization headers.
     *
     * @see Issuer::validate()
     *
     * @param string|null $token   Optional. Token that needs to be validated.
     *
     * @return \stdClass
     */
    public function validate(?string $token = null): \stdClass
    {
        return $this->issuer->validate($token);
    }

    /**
     * In case if the Token was not provided it will be retrieved out from Authorization headers.
     * When Token is retrieved it checks whether the token decodes correctly and passes all checks,
     * after it can be successfully invalidated, so the next time this token won't be valid for a user.
     *
     * @param string|null $token Optional. Token that needs to be invalidated.
     *
     * @return bool
     */
    public function invalidate(?string $token = null): bool
    {
        return $this->issuer->invalidate($token);
    }

    /**
     * Retrieves Token from Authorization headers.
     *
     * @see Issuer::retrieveToken()
     *
     * @return string
     */
    public function retrieveToken(): string
    {
        return $this->issuer->retrieveToken();
    }

    /**
     * Validates the passed token.
     *
     * @param string $token Bearer Token.
     *
     * @see Issuer::validateToken()
     *
     * @return \stdClass
     */
    public function validateToken(string $token): \stdClass
    {
        return $this->issuer->validateToken($token);
    }

    /**
     * Authenticate a user, confirming the login credentials are valid.
     *
     * @param string $username User's username or email address.
     * @param string $password User's password.
     *
     * @see Issuer::issueByCredentials()
     *
     * @return array
     */
    public function issueByCredentials(string $username, string $password): array
    {
        return $this->issuer->issueByCredentials($username, $password);
    }

    /**
     * Issues a token for a User.
     *
     * @param int|string|\WP_User $user The vague user value, int is an ID, string could be either login or email.
     *
     * @see Issuer::issueFor()
     */
    public function issueFor($user): array
    {
        return $this->issuer->issueFor($user);
    }

    /**
     * @param string $namespace
     * @param string $rest_base
     *
     * @return void
     */
    protected function registerRoutes(string $namespace, string $rest_base): void
    {
        $this->routeResolver
            ? call_user_func($this->routeResolver, $namespace, $rest_base, $this)
            : ( new AuthController($namespace, $rest_base, $this) )->register_routes();
    }

    protected function registerUserResolver(): void
    {
        /**
         * Filters the current user.
         *
         * The default filters use this to determine the current user from the
         * request's cookies, if available.
         *
         * Returning a value of false will effectively short-circuit setting
         * the current user.
         *
         * @param int|false $user_id User ID if one has been determined, false otherwise.
         */
        add_filter('determine_current_user', function ($user_id) {
            if ($user_id) {
                return $user_id;
            }

            try {
                if ($this->middleware->shouldBeGuarded($_SERVER['REQUEST_URI'])) {
                    return $this->issuer->validate()->data->user->id;
                }
            } catch (Exceptions\TokenInvalid $e) {
                $this->user_resolver_error = new \WP_Error(
                    'jwt_token_invalid',
                    $e->getMessage(),
                    [ 'status' => \WP_Http::FORBIDDEN ]
                );
            } catch (Exceptions\Unauthorized $e) {
                $this->user_resolver_error = new \WP_Error(
                    'jwt_user_not_authorized',
                    $e->getMessage(),
                    [ 'status' => \WP_Http::UNAUTHORIZED ]
                );
            } catch (\Exception $e) {
                $this->user_resolver_error = new \WP_Error(
                    'jwt_token_error',
                    $e->getMessage(),
                    [ 'status' => \WP_Http::INTERNAL_SERVER_ERROR ]
                );
            }

            // Return as it was before.
            return $user_id;
        });

        /**
         * Filters the pre-calculated result of a REST API dispatch request.
         *
         * Allow hijacking the request before dispatching by returning a non-empty. The returned value
         * will be used to serve the request instead.
         *
         * @param mixed $result Response to replace the requested version with. Can be anything
         *                                 a normal endpoint can return, or null to not hijack the request.
         */
        add_filter('rest_pre_dispatch', function ($result) {
            if (is_wp_error($this->user_resolver_error)) {
                return $this->user_resolver_error;
            }

            return $result;
        }, 10);
    }

    protected function registerMiddlewares(): void
    {
        $this->middleware->engage();
    }
}
