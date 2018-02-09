<?php

/**
 * Class SidnXmlWhoisDescription
 *
 * Text object for WHOIS-output parts
 */
class SidnXmlWhoisDescription {

	public $lang = 'nl-NL';
	public $format = 'PLAIN';
	public $description = ''; // the text content

	public function __construct($lang, $format, $desc) {
		// init
		$this->lang = $lang;
		$this->format = $format;
		$this->description = $desc;
	}

	public function get_lang() {
		return $this->lang;
	}

	public function get_format() {
		return $this->format;
	}

	public function get_desc() {
		return $this->description;
	}
}