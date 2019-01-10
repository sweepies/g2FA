<?php

namespace g2fa;

use PDO;
use PDOException;

class DatabaseInitialization {

	protected $db;

	function __construct($config) {

		// Create DSN
		$dsn = "mysql:host=" .
			$config->mysql->host .
			";dbname=" .
			$config->mysql->database .
			";port=" .
			$config->mysql->port .
			";charset=utf8mb4";

		// Give PDO the DSN, credentials, and some options
		try {
			$db = new PDO($dsn, $config->mysql->user, $config->mysql->password, [
				PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
			]);
		} catch (PDOException $e) {
			die("Unable to connect to database: " . $e->getMessage());
		}

		// Create tables
		$db->beginTransaction();
		$db->exec("CREATE TABLE IF NOT EXISTS g2fa_unconfirmed_users (steamid64 CHAR(17), registration_ip VARCHAR(39), registration_timestamp INT, secret CHAR(16))");
		$db->exec("CREATE TABLE IF NOT EXISTS g2fa_users (steamid64 CHAR(17), registration_ip VARCHAR(39), confirmation_ip VARCHAR(39), last_auth_ip VARCHAR(39), registration_timestamp INT, confirmation_timestamp INT, last_auth_timestamp INT, last_auth_otp CHAR(6), remember_on_device BOOL, secret CHAR(16))");

		if (!$db->commit()) {
			die("Unable to query database.");
		}

		$this->db = $db;
	}

	function getDB() {
		return $this->db;
	}
}