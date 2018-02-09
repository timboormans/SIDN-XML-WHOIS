<?php

/**
 * Class SidnXmlWhoisContact
 *
 * Contact object for all domain contacts
 */
class SidnXmlWhoisContact {

	public $id = ''; // contact handle
	public $view = ''; // registrars have access to the full view
	public $date = ''; // date of this request
	public $name = '';
	public $email = '';
	public $voice = ''; // phone number
	public $has_address = true;
	public $street = '';
	public $postal_code = '';
	public $city = '';
	public $country_code = 'NL';
	public $country_name = 'Nederland';
	public $contact_type = 'unknown'; // see $possible_types below
	private $possible_types = array('registrant', 'admin', 'tech');

	public function __construct($handle, $view, $date, $name, $email, $voice, $street, $postal_code, $city, $cc, $cn, $contact_type = 'unknown') {
		// init
		$this->id = $handle;
		$this->view = $view;
		$this->date = $date;
		$this->name = $name;
		$this->email = $email;
		$this->voice = $voice;
		$this->street = $street;
		$this->postal_code = $postal_code;
		$this->city = $city;
		$this->country_code = $cc;
		$this->country_name = $cn;
		if(strlen($street) > 0) {
			$this->has_address = true;
		} else {
			$this->has_address = false;
		}
		if(in_array($contact_type, $this->possible_types))
			$this->contact_type = $contact_type;
		else
			$this->contact_type = 'unknown';
	}

	public function get_handle() {
		return $this->id;
	}
}