"""
The `~certbot_dns_rfc2136_waitdns.dns_rfc2136_waitdns` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using RFC 2136 Dynamic Updates.
It also wait for the propagation by checking stub resolver for all primary name server
declared in the zone

.. note::
   The plugin is not installed by default. 
   It use certbot_dns_rfc2136.dns_rfc2136 plugin and is inspired by 
   https://github.com/JulienPalard/dnswait code to wait DNS propagation.

Named Arguments
---------------

===================================== =====================================
``--dns-rfc2136-credentials``         RFC 2136 credentials_ INI file.
                                      (Required)
``--dns-rfc2136-propagation-seconds`` The number of seconds to wait for DNS
                                      to propagate before checking DNS 
                                      propagation (Default: 60)
``--dns-rfc2136-propagation-retry``   Number of retry of propagation delay
                                      before giving up and continue the 
                                      ACME process (Default: 6)
===================================== =====================================

More Documentation
------------------

Since we use the certbot_dns_rfc2136 authentificator plugin, see also their doc
"""
