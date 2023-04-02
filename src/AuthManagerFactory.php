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

use Psr\Container\ContainerInterface;

class AuthManagerFactory
{
    public function __construct(protected ContainerInterface $container)
    {
    }

    public function guard(string $guard): AuthManager
    {
        return new AuthManager($this->container, $guard);
    }
}
