#!/usr/bin/env php
<?php
// Please use chmod +x on me ;-)
// Internal test: ./xxe-php
// Own test: ./xxe-php /path/to/attack.xml

// A stream prefix we will both use for the default test and as an example
// when a test fails.
// You can use php://filter to apply filters before the file contents are
// returned.
// This can be useful to ensure all data can be recovered properly.
// E.g.:    php://filter/read=convert.base64-encode/resource=/etc/passwd
// @see http://nl1.php.net/manual/en/wrappers.php.php#refsect2-wrappers.php-unknown-unknown-unknown-unknown-unknown-unknown-descriptiot
$streamPrefix = 'file://';

// The first argument, our current script, is of no use to us.
$arguments = array_slice($argv, 1);
$xmlFile = current($arguments);

// Create an insecure target.
if (empty($xmlFile)) {
    $target = tempnam(
        sys_get_temp_dir(),
        'xxe-php-target'
    );

    // Put some data in the target.
    file_put_contents($target, 'Sensitive data');

    $streamPath = "{$streamPrefix}{$target}";

    $xml = '<!DOCTYPE scan ['
        . '<!ENTITY test SYSTEM "'
        . $streamPath
        . '">]><scan>&test;</scan>';
} else {
    $xml = file_get_contents($xmlFile);
}

// Make sure we can fetch external entities.
// @see http://nl1.php.net/manual/en/function.libxml-disable-entity-loader.php
libxml_disable_entity_loader(false);

// Catch any and all libxml errors
// @see http://nl1.php.net/manual/en/function.libxml-use-internal-errors.php
libxml_use_internal_errors(false);

// Create a new xml parser.
// @see http://nl1.php.net/manual/en/function.xml-parser-create.php
$parser = xml_parser_create('UTF-8');

// A list of gathered external entities and their contents.
$externalEntities = array();

/**
 * A custom external entity handler.
 *
 * @param resource $parser
 * @param string $openEntityNames
 * @param string $base
 * @param string $systemId
 * @param string $publicId
 * @return integer
 * @see http://nl1.php.net/manual/en/function.xml-set-external-entity-ref-handler.php
 */
function externalEntityRefHandler(
    $parser,
    $openEntityNames,
    $base,
    $systemId,
    $publicId
) {
    global $externalEntities;

    if (!empty($systemId)) {
        $externalEntities[$openEntityNames] = @file_get_contents($systemId);
    }

    return (integer) (
        !empty($publicId)
        || !empty($externalEntities[$openEntityNames])
    );
}

// Set a custom entity handler.
// @see http://php.net/manual/en/example.xml-external-entity.php
// @see http://nl1.php.net/manual/en/function.xml-set-external-entity-ref-handler.php
xml_set_external_entity_ref_handler($parser, "externalEntityRefHandler");

// Parse the XML.
if (xml_parse($parser, $xml, true) === 1) {
    // Success.
    echo 'These are the results of your XML attack:' . PHP_EOL . PHP_EOL;

    var_dump($externalEntities);
} else {
    echo 'Sadly, the XXE attack did not work. Try again ;-)' . PHP_EOL;
    echo 'Here is an example of a SYSTEM entity:' . PHP_EOL;
    echo "{$streamPrefix}/etc/passwd" . PHP_EOL;
}

// Free the parser.
// @see http://nl1.php.net/manual/en/function.xml-parser-free.php
xml_parser_free($parser);

// Clean up temporary files.
if (isset($target)) {
    unlink($target);
}
