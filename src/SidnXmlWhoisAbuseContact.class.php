<?php

/**
 * Class SidnXmlWhoisAbuseContact
 *
 * Contact object for abuse
 */
class SidnXmlWhoisAbuseContact {

	public $date = ''; // date of this request
    public $voice = ''; // phone number
	public $email = '';

	public function __construct($date, $voice, $email) {
		// init
        $this->date = $date;
        $this->voice = $voice;
		$this->email = $email;
	}

}