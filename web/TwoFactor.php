<?php

namespace g2fa;

require("vendor/autoload.php");
require_once("DatabaseInitialization.php");

class TwoFactor {

	private $config;
	private $dbInit;
	private $db;
	private $googleAuthenticator;
	
	function __construct($config) {

		$this->config = $config;
		$this->dbInit = new DatabaseInitialization($config);
		$this->db = $this->dbInit->getDB();
		$this->googleAuthenticator = new \PHPGangsta_GoogleAuthenticator();
	}

	function createSecret($steamid64, $ip) {

		try {
			$secret = $this->googleAuthenticator->createSecret();
		} catch (\Exception $e) {
			die("Exception when creating 2FA secret");
		}

		$registration_timestamp = time();
		$data = array((string) $steamid64, $ip, $registration_timestamp, $secret);

		// Add row to unconfirmed users
		$stmt = $this->db->prepare("INSERT INTO g2fa_unconfirmed_users (steamid64, registration_ip, registration_timestamp, secret) VALUES (?, ?, ?, ?)");
		$stmt->execute($data);
		if ($stmt->rowCount() === 0) {
			return array("success" => false, "errorCode" => $stmt->errorCode(), "errorInfo" => $stmt->errorInfo());
		}
		return array("success" => true, "registration_timestamp" => $registration_timestamp, "secret" => $secret, "qr_url" => $this->googleAuthenticator->getQRCodeGoogleUrl($this->config->service_name, $secret));
		
	}

	function getQrCode($secret) {

	}

	function confirmUser($steamid64, $registration_timestamp, $otp, $remember_on_device, $client_ip) {

		// Delete expired unconfirmed users
		$stmt = $this->db->prepare("DELETE FROM g2fa_unconfirmed_users WHERE registration_timestamp < ?");
		$stmt->execute([strtotime("-1 hour")]);

		// Get data for cooresponding user
		$stmt = $this->db->prepare("SELECT * FROM g2fa_unconfirmed_users WHERE steamid64=?");
		$stmt->execute([$steamid64]);
		if ($stmt->rowCount() === 0) {
			return array("success" => false, "error" => "User not found in database", "httpCode" => 404);
		}
		$data = $stmt->fetch();

		// Validate information
		if (!$registration_timestamp === $data['registration_timestamp']) {
			return array("success" => false, "error" => "Invalid registration timestamp", "httpCode" => 403);
		}
		if (!$this->googleAuthenticator->verifyCode($data['secret'], (string) $otp, 2)) {
			return array("success" => false, "error" => "Invalid one time password", "httpCode" => 403);
		}

		// Information correct, move user to confirmed table
		$confirmation_timestamp = time();
		$data = array((string) $steamid64, $data['registration_ip'], $client_ip, $client_ip, $data['registration_timestamp'], $confirmation_timestamp, $confirmation_timestamp, $otp, $remember_on_device, $data['secret']);
		$stmt = $this->db->prepare("INSERT INTO g2fa_users (steamid64, registration_ip, confirmation_ip, last_auth_ip, registration_timestamp, confirmation_timestamp, last_auth_timestamp, last_auth_otp, remember_on_device, secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
		$stmt->execute($data);

		// Delete from unconfirmed table
		$stmt = $this->db->prepare("DELETE FROM g2fa_unconfirmed_users WHERE steamid64=?");
		$stmt->execute([$steamid64]);
		return array("success" => true, "confirmation_timestamp" => $confirmation_timestamp, "httpCode" => 200);
		
	}

	function verify($steamid64, $otp, $remember_on_device, $client_ip) {

		// Get data for cooresponding user
		$stmt = $this->db->prepare("SELECT * FROM g2fa_users WHERE steamid64=?");
		$stmt->execute([(string) $steamid64]);

		// Check if user exists
		if ($stmt->rowCount() === 0) {
			return array("success" => false, "error" => "User not found in database", "httpCode" => 404);
		}

		// Get user secret
		$data = $stmt->fetch();
		$secret = $data['secret'];

		// Ensure the same OTP isn't used more than once
		if ($data['last_auth_otp'] == $otp) {
			return array("success" => false, "error" => "Invalid one time password", "httpCode" => 401);
		}

		// Validate OTP
		if (!$this->googleAuthenticator->verifyCode($secret, (string) $otp, 2)) {
			return array("success" => false, "error" => "Invalid one time password", "httpCode" => 401);
		}

		// Update database entry
		$timestamp = time();
		$data = array($client_ip, $timestamp, $otp, $remember_on_device, $steamid64);
		$stmt = $this->db->prepare("UPDATE g2fa_users SET last_auth_ip = ?, last_auth_timestamp = ?, last_auth_otp = ?, remember_on_device = ? WHERE steamid64=?");
		$stmt->execute($data);

		return array("success" => true, "last_auth_timestamp" => $timestamp, "httpCode" => 200);
	
	}
}