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

abstract class UserProvider implements UserProviderInterface
{
    public function __construct(protected string $guard)
    {
    }

    public function setJwtConfig(): array
    {
        return [];
    }

    public function validateToken(array $payload): array
    {
        return $this->getInfo($payload);
    }
}
