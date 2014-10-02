mccs
====

Metadata monitoring service

A script that tries to verify whether SAML2 IdPs have read and understood metadata.

Bascially it acts as a SP and tries to contact all the IdPs in a metadata file.
A positive response when contacting an IdP is the display of a login page.
Negative responses can be:

- either an HTTP status code >= 400,
- a '200 OK' but where the text is an error message or
- failed connection

The output is either in a Nagios format or a simple text format.
One IdP per line.
