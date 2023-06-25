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

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpMessage\Exception\UnauthorizedHttpException;
use Hyperf\HttpServer\Contract\RequestInterface;

class JwtFactory
{
    protected ConfigInterface $config;

    protected RequestInterface $request;

    protected Token $token;

    protected string $alg;

    protected string $secret;

    protected string $iss;

    protected string $aud;

    protected int $exp;

    protected string $header;

    protected string $prefix;

    public function __construct(protected string $guard)
    {
        $this->setJwtConfig();
    }

    public function setJwtConfig(array $config = [])
    {
        $this->alg = $config['alg'] ?? $this->getConfig(sprintf('auth.%s.jwt.alg', $this->guard));
        $this->secret = $config['secret'] ?? $this->getConfig(sprintf('auth.%s.jwt.secret', $this->guard));
        $this->iss = $config['iss'] ?? $this->getConfig(sprintf('auth.%s.jwt.iss', $this->guard), 'hapi');
        $this->aud = $config['aud'] ?? $this->getConfig(sprintf('auth.%s.jwt.aud', $this->guard), 'hapi');
        $this->exp = $config['exp'] ?? (int) $this->getConfig(sprintf('auth.%s.jwt.exp', $this->guard), 7200);
        $this->header = $config['header'] ?? $this->getConfig(sprintf('auth.%s.jwt.header', $this->guard), 'authorization');
        $this->prefix = $config['prefix'] ?? $this->getConfig(sprintf('auth.%s.jwt.prefix', $this->guard), 'bear');
    }

    public function encode(array $user): string
    {
        $timestamp = time();
        $payload = [
            'iss' => $this->iss,
            'aud' => $this->aud,
            'iat' => $timestamp,
            'exp' => $timestamp + $this->exp,
        ];
        $payload = array_replace($user, $payload);
        return JWT::encode($payload, $this->secret, $this->alg);
    }

    public function decode(int $leeway = 0): array
    {
        $key = new Key($this->secret, $this->alg);
        JWT::$leeway = $leeway;
        $payloadObj = JWT::decode($this->getToken()->toString(), $key);
        return (array) $payloadObj;
    }

    public function getToken(): Token
    {
        if (empty($this->token)) {
            $this->parseToken();
        }

        return $this->token;
    }

    public function setToken(Token $token): static
    {
        $this->token = $token;

        return $this;
    }

    public function parseToken(): static
    {
        if (empty($this->request)) {
            $this->request = make(RequestInterface::class);
        }
        $header = $this->request->header($this->header);
        if ($header and preg_match('/' . $this->prefix . '\s*(\S+)\b/i', $header, $matches)) {
            $token = $matches[1];
            return $this->setToken(new Token($token));
        }
        throw new UnauthorizedHttpException('The token could not be parsed from the request');
    }

    protected function getConfig(string $key, mixed $default = null)
    {
        if (empty($this->config)) {
            $this->config = make(ConfigInterface::class);
        }
        return $this->config->get($key, $default);
    }
}
