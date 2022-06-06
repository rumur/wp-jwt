# wp-jwt
WordPress JSON Web Token Authentication tool.

### Minimum Requirements:
 - PHP: 7.4+
 - WordPress: 5.3+

## Installation

```composer require rumur/wp-jwt```

### Themosis 2.x
```php console vendor:publish --provider='Rumur\WordPress\JsonWebToken\JWTServiceProvider'```

### Sage 10.x
```wp acorn vendor:publish --provider='Rumur\WordPress\JsonWebToken\JWTServiceProvider'```

## License
  This package is licensed under the MIT License - see the [LICENSE.md](https://github.com/rumur/wp-jwt/blob/master/LICENSE) file for details.