<?php

require_once("TwoFactor.php");

function get_client_ip() {
	if (isset($_SERVER['HTTP_CLIENT_IP']))
		return $_SERVER['HTTP_CLIENT_IP'];
	else if(isset($_SERVER['HTTP_X_FORWARDED_FOR']))
		return $_SERVER['HTTP_X_FORWARDED_FOR'];
	else if(isset($_SERVER['HTTP_X_FORWARDED']))
		return $_SERVER['HTTP_X_FORWARDED'];
	else if(isset($_SERVER['HTTP_FORWARDED_FOR']))
		return $_SERVER['HTTP_FORWARDED_FOR'];
	else if(isset($_SERVER['HTTP_FORWARDED']))
		return $_SERVER['HTTP_FORWARDED'];
	else if(isset($_SERVER['REMOTE_ADDR']))
		return $_SERVER['REMOTE_ADDR'];
	else
		return 'UNKNOWN';
}

function getResponse() {

	// Set API headers
	header("Access-Control-Allow-Origin: *");
	header("Content-Type: application/json; charset=UTF-8");
	header("Access-Control-Allow-Methods: POST");

	// Check for correct method
	if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
		http_response_code(405);
		return array("error" => "use POST");
    }

	// Get and check config
	$config = json_decode(file_get_contents("config.json"));
	if ($config === NULL) {
		http_response_code(500);
		return array("error" => "Unable to read configuration");
	}

	// Check for present Authorization header
	if (!isset($_SERVER["HTTP_AUTHORIZATION"])) {
		http_response_code(401);
		return array("error" => "Missing API key");
	}

	// Check API key
	$authData = explode(" ", $_SERVER["HTTP_AUTHORIZATION"], 2);
	if ($authData[0] !== "Bearer" || $authData[1] !== $config->api_key) {
		http_response_code(401);
		return array("error" => "Invalid API key");
	}

	// Get and check posted data
	$jsonData = file_get_contents("php://input");
	if (strlen($jsonData) === 0) {
		http_response_code(400);
		return array("error" => "Empty request body");
	}
	$data = json_decode(file_get_contents("php://input"));
	if ($data === NULL) {
		http_response_code(400);
		return array("error" => "Invalid request body");
	}

	// Check if data is complete
	$missingParams = array();
	if (!property_exists($data, "steamid64")) {
		array_push($missingParams, "steamid64");
	}

	$paramsMissing = count($missingParams);
	if (count($missingParams) > 0) {
		http_response_code(400);
		return array("error" => "Missing parameter" . ($paramsMissing > 1 ? "s" : ""), "parameters" => $missingParams);
	}

	// Create 2FA object
	$twofactor = new \g2fa\TwoFactor($config);
	// Create secret and store in DB as unconfirmed
	$twofactorResponse = $twofactor->createSecret($data->steamid64, get_client_ip());

	if (!$twofactorResponse['success']) {
		http_response_code(500);
		return array("error" => "A database error occurred", "error_code" => $twofactorResponse['errorCode']);
	}

	// Return timestamp (for syncing device to server time) and secret
	http_response_code(200);
	return array("registration_timestamp" => $twofactorResponse['registration_timestamp'], "secret" => $twofactorResponse['secret'], "qr_url" => $twofactorResponse['qr_url']);
}

print_r(json_encode(getResponse()));
