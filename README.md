Inner-Cryptography
=======

Introduction
------------

This service provides methods to encrypt/decrypt datas, both in a simple way or with a stronger hash comparison.

Requirements
------------

* [Zend Framework 2](https://github.com/zendframework/zf2) (latest master)

Installation
------------

### Main Setup

#### By cloning project (not recommended)

1. Clone this project into your `./vendor/` directory.

#### With composer

    ```json
    "require": {
    	// ...
        "qbonaventure/Inner-Cryptography": "dev-master"
    }
	"autoload": {
		"psr-4": {// ...
			"QBonaventure\\InnerCryptography\\": "vendor/qbonaventure/inner-cryptography/src/"
		}
	}
    ```
    
#### Post installation

1. Enabling it in your `{application|module}.config.php`file.

    ```php
    <?php
    return array(
    	// ...
        'service_manager' => array(
	        'factories' => array(
	         	// ...
    			'CryptographyInterface'	=> 'QBonaventure\InnerCryptography\ServiceFactory',	
	        ),
        ),
        // ...
    );
    ```

2. Copy config/cryptography.global.php.dist to your config directory
3. Remove the .dist extension from these files and fill in the blanks (see "Configuration")


### Configuration

    ```php
	<?php
	return array(
		'cryptography' => array(
			'key'	=> '',
			'iv'	=> '',
			'method'	=> 'aes-512-cbc',
			'hashAlgo'	=> 'sha256',
			'hashCost'		=> null,
		),
	);
	```


- "key" must be a long string of random letters and numbers, like 200+
- "iv" is a vector that can consisted of about 20 random letters and numbers
- "method" is the encryption method, default is "aes-512-cbc"
- "hashAlgo" is the hashing algorithm used for encryption, default is "sha256"
- "hashCost" is the hash function cost for password_hash(). "null" defaults to the function default : 10 
