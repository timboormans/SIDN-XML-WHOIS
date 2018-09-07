<?php

/**
 * Class SidnXmlWhoisReseller
 *
 * Reseller object for WHOIS output
 */
class SidnXmlWhoisReseller {

	public $date = ''; // date of this request
	public $name = '';
	public $street = '';
	public $postal_code = '';
	public $city = '';
	public $country_name = ''; // Nederland
	public $country_code = ''; // NL
	public $country_lang = ''; // nl-NL

	public function __construct($date, $name, $street, $postal_code, $city, $cc, $cl, $cn) {
		// init
		$this->date = $date;
		$this->name = $name;
		$this->street = $street;
		$this->postal_code = $postal_code;
		$this->city = $city;
		$this->country_code = $cc;
		$this->country_lang = $cl;
		$this->country_name = $cn;
	}
}