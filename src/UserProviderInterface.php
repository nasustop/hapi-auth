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

interface UserProviderInterface
{
    public function getInfo(array $payload): array;

    public function login(array $inputData): array;

    public function logout(array $payload): bool;

    public function validateToken(array $payload): array;

    public function setJwtConfig(): array;
}
