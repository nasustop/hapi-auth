<?php

declare(strict_types=1);
/**
 * This file is part of Hapi.
 *
 * @link     https://www.nasus.top
 * @document https://wiki.nasus.top
 * @contact  xupengfei@xupengfei.net
 * @license  https://github.com/nasustop/hapi-auth/blob/master/LICENSE
 */
namespace Nasustop\HapiAuth;

use Hyperf\HttpMessage\Exception\UnauthorizedHttpException;

class Token
{
    public function __construct(protected string $token)
    {
    }

    /**
     * Get the token when casting to string.
     */
    public function toString(): string
    {
        return $this->check();
    }

    /**
     * Check the structure of the token.
     */
    public function check(): string
    {
        $this->validateStructure();
        return $this->token;
    }

    /**
     * Helper function to return a boolean.
     */
    public function isValid(): bool
    {
        try {
            $this->check();
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    protected function validateStructure(): self
    {
        $parts = explode('.', $this->token);

        if (count($parts) !== 3) {
            throw new UnauthorizedHttpException('Wrong number of segments');
        }

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 or implode('.', $parts) !== $this->token) {
            throw new UnauthorizedHttpException('Malformed token');
        }

        return $this;
    }
}
