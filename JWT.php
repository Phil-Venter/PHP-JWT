<?php

class JWT {
	protected $secret;
	protected $issuer;

	function __construct(string $secret = '', string $issuer = '') {
		$this->secret = $secret;
		$this->issuer = $issuer;
	}

	public function generate(array $payload, array $headers = [], array $options = []): string
	{
		// if no secret is passed use global secret passed in constructor
		if(!isset($options['secret']) || !is_string($options['secret']) || $this->istrlen($options['secret']) <= 0) {
			$options['secret'] = $this->secret;
		}

		// set algorithm JWT is generated with to ensure validity
		$headers['alg'] = 'HS256';
		$headers['typ'] = 'JWT';

		// set issuer if not specified in payload but is in options
		if (!isset($payload['iss']) && isset($options['iss'])) {
			if (is_string($options['iss']) && $this->istrlen($options['iss']) > 0) {
				$payload['iss'] = $options['iss'];
			} elseif ((is_bool($options['iss']) && $options['iss']) || !is_bool($options['iss'])) {
				$payload['iss'] = $this->issuer;
			}
		}

		// set issued at time if not specified in payload but is in options
		if (!isset($payload['iat']) && isset($options['iat'])) {
			if (is_integer($options['iat'])) {
				$payload['iat'] = $options['iat'];
			} elseif (is_string($options['iat'])) {
				$payload['iat'] = strtotime($options['iat']);
			} elseif ((is_bool($options['iat']) && $options['iat']) || !is_bool($options['iat'])) {
				$payload['iat'] = time();
			}
		}

		// generate encoded header and payload
		$headers_encoded = $this->base64url_encode(json_encode($headers));
		$payload_encoded = $this->base64url_encode(json_encode($payload));

		// generate signature and encode signature
		$signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $options['secret'], true);
		$signature_encoded = $this->base64url_encode($signature);

		return "$headers_encoded.$payload_encoded.$signature_encoded";
	}

	public function extract(string $jwt, array $options = []): bool|array {
		// validate JWT before decoding
		if (!$this->validate($jwt, $options)) {
			return false;
		}

		// split the JWT
		$tokenParts = explode('.', $jwt);
		$json_header = base64_decode($tokenParts[0]);
		$json_payload = base64_decode($tokenParts[1]);
		$signature = $tokenParts[2];

		$header = json_decode($json_header, true);
		$payload = json_decode($json_payload, true);

		return compact('header', 'payload', 'signature');
	}

	public function validate(string $jwt, array $options = []): bool {
		// if no secret is passed use global secret passed in constructor
		if(!isset($options['secret']) || !is_string($options['secret']) || $this->istrlen($options['secret']) <= 0) {
			$options['secret'] = $this->secret;
		}

		// split the JWT
		$tokenParts = explode('.', $jwt);
		$header = base64_decode($tokenParts[0]);
		$payload = base64_decode($tokenParts[1]);
		$signature_provided = $tokenParts[2];

		$json_payload = json_decode($payload, true);

		// check if issuer specified is correct
		if (isset($options['iss'])) {
			if (!isset($json_payload['iss'])) {
				return false;
			}
			if (is_string($options['iss']) && $this->istrlen($options['iss']) > 0) {
				if ($json_payload['iss'] !== $options['iss']) {
					return false;
				}
			} elseif ((is_bool($options['iss']) && $options['iss']) || !is_bool($options['iss'])) {
				if ($json_payload['iss'] !== $this->issuer) {
					return false;
				}
			}
		}

		// check the expiration time if it is set
		if(isset($json_payload['exp'])) {
			if(($json_payload['exp'] - time()) < 0) {
				return false;
			}
		}

		// check the not before time if it is set
		if(isset($json_payload['nbf'])) {
			if(($json_payload['nbf'] - time()) > 0) {
				return false;
			}
		}

		// build a signature based on the header and payload using the secret
		$base64_url_header = $this->base64url_encode($header);
		$base64_url_payload = $this->base64url_encode($payload);
		$signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $options['secret'], true);
		$base64_url_signature = $this->base64url_encode($signature);

		// verify it matches the signature provided in the JWT
		return $base64_url_signature === $signature_provided;
	}

	protected function base64url_encode(string $str): string
	{
		return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
	}

	protected function istrlen(string $str): int
	{
		return mb_strlen(trim($str), 'UTF-8');
	}
}
