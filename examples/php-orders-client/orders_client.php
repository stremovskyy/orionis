<?php

declare(strict_types=1);

function env_value(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false || $value === '' ? $fallback : $value;
}

function status_code(array $headers): int
{
    if ($headers === []) {
        return 0;
    }

    if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', $headers[0], $matches) !== 1) {
        return 0;
    }

    return (int) $matches[1];
}

function http_request(string $method, string $url, array $headers, string $body): array
{
    $context = stream_context_create([
        'http' => [
            'method' => $method,
            'header' => implode("\r\n", $headers) . "\r\n",
            'content' => $body,
            'timeout' => 10,
            'ignore_errors' => true,
        ],
    ]);

    $raw = file_get_contents($url, false, $context);
    if ($raw === false) {
        throw new RuntimeException("HTTP request failed before response: {$method} {$url}");
    }

    /** @var array<int, string> $http_response_header */
    return [status_code($http_response_header ?? []), $raw];
}

function request_token(
    string $tokenURL,
    string $clientID,
    string $clientSecret,
    string $audience,
    string $scope
): array {
    $form = http_build_query([
        'grant_type' => 'client_credentials',
        'audience' => $audience,
        'scope' => $scope,
    ], '', '&', PHP_QUERY_RFC3986);

    [$status, $raw] = http_request('POST', $tokenURL, [
        'Authorization: Basic ' . base64_encode($clientID . ':' . $clientSecret),
        'Content-Type: application/x-www-form-urlencoded',
        'Accept: application/json',
    ], $form);

    if ($status !== 200) {
        throw new RuntimeException("token request failed: status={$status} body={$raw}");
    }

    $token = json_decode($raw, true);
    if (!is_array($token)) {
        throw new RuntimeException('token response is not valid JSON: ' . json_last_error_msg());
    }

    if (($token['access_token'] ?? '') === '') {
        throw new RuntimeException('token response is missing access_token');
    }
    if (strcasecmp((string) ($token['token_type'] ?? ''), 'Bearer') !== 0) {
        throw new RuntimeException('token response has unexpected token_type=' . (string) ($token['token_type'] ?? ''));
    }
    if ((int) ($token['expires_in'] ?? 0) <= 0) {
        throw new RuntimeException('token response has invalid expires_in=' . (string) ($token['expires_in'] ?? ''));
    }

    return $token;
}

function create_invoice(string $billingURL, string $accessToken): array
{
    $body = json_encode([
        'order_id' => 'ord_demo_001',
        'amount' => 1500,
    ], JSON_THROW_ON_ERROR);

    [$status, $raw] = http_request('POST', $billingURL, [
        'Authorization: Bearer ' . $accessToken,
        'Content-Type: application/json',
        'Accept: application/json',
    ], $body);

    if ($status < 200 || $status >= 300) {
        throw new RuntimeException("billing request failed: status={$status} body={$raw}");
    }

    return [$status, $raw];
}

$tokenURL = env_value('ORIONIS_TOKEN_URL', 'http://localhost:8080/oauth/token');
$billingURL = env_value('BILLING_URL', 'http://localhost:8081/invoices');
$clientID = env_value('ORIONIS_CLIENT_ID', 'orders-service');
$clientSecret = env_value('ORIONIS_CLIENT_SECRET', 'orders-local-secret-change-me');
$audience = env_value('ORIONIS_AUDIENCE', 'billing-api');
$scope = env_value('ORIONIS_SCOPE', 'billing.invoice.create');

$token = request_token($tokenURL, $clientID, $clientSecret, $audience, $scope);
[$status, $raw] = create_invoice($billingURL, (string) $token['access_token']);

echo "status={$status}\n";
echo rtrim($raw) . "\n";
