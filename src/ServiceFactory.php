<?php
namespace QBonaventure\InnerCryptography;

use Zend\ServiceManager\FactoryInterface;
use Zend\ServiceManager\ServiceLocatorInterface;
use QBonaventure\InnerCryptography\Service;
use Zend\Config\Config;
				
/**
 * Class Factory
 * @package QBonaventure\InnerCryptography\Service
 */
    class ServiceFactory implements FactoryInterface
    {
        /**
         * @param ServiceLocatorInterface $locator
         * @return Service
         */
        public function createService(ServiceLocatorInterface $locator)
        {
            $config 		= $locator->get('config')['cryptography'];
            return new Service(new Config($config));
        }
    }