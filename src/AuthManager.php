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

use Hyperf\Context\ApplicationContext;
use Hyperf\Contract\ConfigInterface;

class AuthManager
{
    protected JwtFactory $jwtFactory;

    protected ConfigInterface $config;

    protected UserProviderInterface $userProvider;

    protected array $payload;

    public function __construct(protected string $guard)
    {
        $providerName = $this->getConfig("auth.{$guard}.provider");
        if (! class_exists($providerName)) {
            throw new \InvalidArgumentException("auth.{$guard}.provider is not exists");
        }
        $provider = new $providerName($guard);
        if (! $provider instanceof UserProviderInterface) {
            throw new \InvalidArgumentException("auth.{$guard}.provider is not UserProviderInterface type class");
        }
        $this->userProvider = $provider;
    }

    public function attempt(array $inputData): string
    {
        $user = $this->userProvider->login($inputData);
        return $this->getJwtFactory()->encode($user);
    }

    public function user(): array
    {
        $payload = $this->payload();
        return $this->userProvider->getInfo($payload);
    }

    public function logout(): bool
    {
        $payload = $this->payload();
        return $this->userProvider->logout($payload);
    }

    public function payload(int $leeway = 0): array
    {
        if (empty($this->payload)) {
            $this->payload = $this->getJwtFactory()->decode($leeway);
        }
        return $this->payload;
    }

    /**
     * refresh token.
     */
    public function refresh(int $leeway = 0): string
    {
        if (empty($leeway)) {
            $leeway = $this->getConfig(sprintf('auth.%s.jwt.leeway', $this->guard), 300);
        }
        $payload = $this->getJwtFactory()->decode($leeway);
        return $this->getJwtFactory()->encode($payload);
    }

    /**
     * validateToken.
     */
    public function validateToken(string $token): array
    {
        $payload = $this->getJwtFactory()->setToken(new Token($token))->decode();
        return $this->userProvider->validateToken($payload);
    }

    /**
     * get JwtFactory.
     */
    protected function getJwtFactory(): JwtFactory
    {
        if (empty($this->jwtFactory)) {
            $this->jwtFactory = new JwtFactory($this->guard);
            $this->jwtFactory->setJwtConfig($this->userProvider->setJwtConfig());
        }
        return $this->jwtFactory;
    }

    protected function getConfig(string $key, mixed $default = null)
    {
        if (empty($this->config)) {
            $this->config = make(ConfigInterface::class);
        }
        return $this->config->get($key, $default);
    }
}
