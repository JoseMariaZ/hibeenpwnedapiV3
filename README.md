# hibeenpwnedapiV3
Tool to search on haveibeenpwned API V3

To register get API key: https://haveibeenpwned.com/API/Key

Usage:

To search for one email: python hibeenpwnedapiv3.py -e your@email.com

To search multiple emails on a list (One per line): python hibeenpwnedapiv3.py -f /path/to/list

To search all the domains breached on HIBPWNED: python hibeenpwnedapiv3.py -d All

To search for an especific domain: python hibeenpwnedapiv3.py -d domain.com

References:
https://haveibeenpwned.com/API/v3
https://github.com/m0nkeyplay
https:/gist.github.com/mikerr/6389549
