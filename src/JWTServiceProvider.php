<?php

namespace Rumur\WordPress\JsonWebToken;

use Illuminate\Support\ServiceProvider;

class JWTServiceProvider extends ServiceProvider
{
	/**
	 * Register notice services.
	 *
	 * @return void
	 */
	public function register(): void
	{
		$this->app->singleton('rumur_wp_jwt', function () {
			return new Service(env('JWT_SECRET'), env('JWT_ALGO', 'HS256'));
		});
	}
}