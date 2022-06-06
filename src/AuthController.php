<?php

namespace Rumur\WordPress\JsonWebToken;

use WP_REST_Server;

class AuthController extends \WP_REST_Controller
{
    /**
     * The JWT Service.
     *
     * @var Service
     */
    protected Service $jwt;

    /**
     * Instantiate JWT AuthController.
     *
     * @param string $namespace The namespace where all endpoints are going to be registered, e.g. 'jwt/v1'
     * @param string $rest_base The rest_base where all endpoints are going to be registered, e.g. 'auth'
     * @param Service $jwt
     */
    public function __construct(string $namespace, string $rest_base, Service $jwt)
    {
        $this->namespace = $namespace;
        $this->rest_base = $rest_base;

        $this->jwt = $jwt;
    }

    /**
     * Registers the routes for the objects of the controller.
     *
     * @see register_rest_route()
     */
    public function register_routes(): void
    {
        register_rest_route(
            $this->namespace,
            '/' . $this->rest_base . '/login',
            [
                [
                    'methods'             => WP_REST_Server::CREATABLE,
                    'callback'            => [ $this, 'get_item' ],
                    'permission_callback' => [ $this, 'get_item_permissions_check' ],
                    'args'                => [
						'username'  => [
							'type' => 'string',
						],
						'password'  => [
							'type' => 'string',
						],
                    ],
                ]
            ]
        );

        register_rest_route(
            $this->namespace,
            '/' . $this->rest_base . '/validate',
            [
                [
                    'methods'  => WP_REST_Server::CREATABLE,
                    'callback' => [ $this, 'validate_token' ],
                    'permission_callback' => '__return_true',
                ]
            ]
        );

        register_rest_route(
            $this->namespace,
            '/' . $this->rest_base . '/logout',
            [
                [
                    'methods'             => WP_REST_Server::READABLE,
                    'callback'            => [ $this, 'delete_item' ],
                    'permission_callback' => 'is_user_logged_in',
                ],
            ]
        );
    }
}
