<?php

namespace Rumur\WordPress\JsonWebToken;

use Firebase\JWT\JWT as Provider;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException as ProviderExpiredException;
use Firebase\JWT\BeforeValidException as ProviderBeforeValidException;
use Firebase\JWT\SignatureInvalidException as ProviderSignatureInvalidException;
use Rumur\WordPress\JsonWebToken\Exceptions;

class Issuer
{
    /**
     * Holds a secret for the JWT.
     *
     * @var string|false
     */
    protected string $secret;

    /**
     * Holds an algorithm for the JWT.
     *
     * @var string|false
     */
    protected string $algo;

    /**
     * Instantiate a Token Issuer.
     *
     * @param string|null $secret  Secret Key.
     * @param string|null $algo    Optional. Possible options `ES384`, `ES256`, `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `EdDSA`.
     */
    public function __construct(?string $secret = null, ?string $algo = 'HS256')
    {
        $this->secret = $secret;
        $this->algo = $algo;

        $this->ensureAllSet();
    }

    /**
     * Ensures the Service can operate correctly.
     *
     * @return void
     */
    protected function ensureAllSet(): void
    {
        $errors = [];

        if (! $this->secret) {
            $message = __('Please define `JWT_SECRET` key before use.', 'rumur-jwt');

            _doing_it_wrong(__CLASS__, $message, '1.0.0');

            $errors[] = $message;
        }

        if (! $this->algo) {
            $message = __('Please define `JWT_ALGO` key before use, possible options: `ES384`, `ES256`, `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `EdDSA`.', 'rumur-jwt');

            _doing_it_wrong(__CLASS__, $message, '1.0.0');

            $errors[] = $message;
        }

        if (! empty($errors)) {
            throw new \InvalidArgumentException(implode('\n', $errors));
        }
    }

    /**
     * Checks whether the token decodes correctly and passes all checks.
     * In case if the Token was not provided it will try to retrieve the token from Authorization headers.
     *
     * @see Issuer::retrieveToken()
     * @see Issuer::validateToken()
     *
     * @param string|null $token   Optional. Token that needs to be validated.
     *
     * @return \stdClass
     */
    public function validate(?string $token = null): \stdClass
    {
        if (! $token) {
            $token = $this->retrieveToken();
        }

        return $this->validateToken($token);
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
        try {
            if (! $token) {
                $token = $this->retrieveToken();
            }

            $validated = $this->validateToken($token);

            \WP_Session_Tokens::get_instance($validated->data->user->id)->destroy($validated->jti);

            return true;
        } catch (\Exception $e) {
            // Seems that token is already invalid so just do nothing.
            return true;
        }
    }

    /**
     * Retrieves Token from Authorization headers.
     *
     * @return string
     */
    public function retrieveToken(): string
    {
        /**
         * Looking for the HTTP_AUTHORIZATION header, if not present just return the user.
         * Double check for different auth header string (server dependent)
         */
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? false;

        if (! $auth) {
            throw new Exceptions\MissingAuthorizationHeader('Authorization header is missing.');
        }

        /** The header is provided, lets retrieve the token. */
        [ $token ] = sscanf($auth, 'Bearer %s');

        if (! $token) {
            throw new Exceptions\MissingAuthorizationHeader('Authorization header is malformed.');
        }

        return $token;
    }

    /**
     * Validates the passed token.
     *
     * @param string $token Bearer Token.
     *
     * @return \stdClass
     */
    public function validateToken(string $token): \stdClass
    {
        try {
            /**
             * Some Claims are handled by provider, such as:
             *
             * - exp @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
             * - nbf @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5
             * - iat @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6
             */
            $decoded = Provider::decode($token, new Key($this->secret, $this->algo));

            /**
             * Validate the Issuer Claim
             *
             * @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1
             */
            if ($decoded->iss !== get_bloginfo('url')) {
                throw new Exceptions\TokenInvalid('The issuer does not match');
            }

            /** Validate the user id in the token */
            if (! isset($decoded->data->user->id)) {
                throw new Exceptions\TokenInvalid('User id was not found in the token');
            }

            $decode_user_id = $decoded->data->user->id;

            $user = get_user_by('id', $decode_user_id);

            /** Check if user still exists */
            if (! $user) {
                throw new Exceptions\NotResolvableUser("User id: $decode_user_id no longer available");
            }

            if (! \WP_Session_Tokens::get_instance($user->ID)->verify($decoded->jti)) {
                throw new Exceptions\TokenStale('Token is no longer can be used');
            }

            return $decoded;
        } catch (ProviderBeforeValidException | ProviderExpiredException | ProviderSignatureInvalidException $e) {
            throw new Exceptions\TokenInvalid($e->getMessage());
        }
    }

    /**
     * Authenticate a user, confirming the login credentials are valid.
     *
     * @param string $username User's username or email address.
     * @param string $password User's password.
     *
     * @see wp_authenticate()
     *
     * @return array
     */
    public function issueByCredentials(string $username, string $password): array
    {
        $user = wp_authenticate($username, $password);

        return $this->issueFor($user);
    }

    /**
     * Issues a token for a User.
     *
     * @param int|string|\WP_User $user The vague user value, int is an ID, string could be either login or email.
     */
    public function issueFor($user): array
    {
        $resolved = null;

        if ($user instanceof \WP_User && $user->exists()) {
            $resolved = $user;
        }

        if (! $resolved && is_int($user)) {
            $resolved = get_user_by('id', $user);
        }

        if (! $resolved && is_string($user) && is_email($user)) {
            $resolved = get_user_by('email', $user);
        }

        if (! $resolved && is_string($user)) {
            $resolved = get_user_by('login', $user);
        }

        $issuedAt  = time();
        $notBefore = $issuedAt;
        $expire    = $notBefore + ( DAY_IN_SECONDS * 7 );

        /**
         * Filters the JWT Claims.
         *
         * @link https://www.rfc-editor.org/rfc/rfc7519
         *
         * Allows to extend the default JWT Claims.
         *
         * @param array  $claims Default JWT Claims.
         */
        $token = apply_filters( 'rumur/jwt/token-claims', [
            'iss' => get_bloginfo( 'url' ),
            'iat' => $issuedAt,
            'nbf' => $notBefore,
            'exp' => $expire,
        ] );

        $session_extender = fn(array $data) => array_merge([ 'jwt' => true ], $data);

        /** Extends the information attached to the newly created session. */
        add_filter('attach_session_information', $session_extender);

        $token['jti'] = \WP_Session_Tokens::get_instance($resolved->ID)->create($expire);

        /** Removes the information extender. */
        remove_filter('attach_session_information', $session_extender);

        /**
         * Filters the JWT Token Data.
         *
         * Allows to extend the default JWT User Token data.
         *
         * @param array $data Default JWT User Token data.
         * @param \WP_User $user The User we're issuing token for.
         */
        $token['data'] = apply_filters( 'rumur/jwt/token-data', [
            'user' => [
                'id' => $resolved->ID,
            ],
        ], $user );

        $token = Provider::encode($token, $this->secret, $this->algo);

        return [
            'token'             => $token,
            'user_email'        => $user->data->user_email,
            'user_nicename'     => $user->data->user_nicename,
            'user_display_name' => $user->data->display_name,
        ];
    }
}
