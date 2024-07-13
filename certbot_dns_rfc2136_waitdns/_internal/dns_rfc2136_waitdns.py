"""Vault Let's Encrypt installer plugin."""

import logging

import dns.message
import dns.resolver
import dns.query

from certbot_dns_rfc2136._internal import dns_rfc2136


logger = logging.getLogger(__name__)


def find_authority(qname):
    """Locate the autoritative name server for the given name using a stub
    resolver.
    """
    zone = dns.resolver.zone_for_name(qname)
    return [
        (ns.target, a.address)
        for ns in dns.resolver.resolve(zone, "NS")
        for a in dns.resolver.resolve(ns.target, "A")
    ]


def wait_dns(qname, rdtype, value, retry, sleep_delay):
    """Wait for the authoritative name server for the given domain to have
    the given value.
    """

    authorities = find_authority(qname)
    logger.info("%d authoritative name servers to check.", len(authorities))
    retrys = {ns[1]: 0 for ns in authorities}
    while authorities:
        authority_name, authority_address = authorities.pop(0)
        logger.debug("Checking %s", authority_name)
        response = dns.query.udp(
            dns.message.make_query(qname, rdtype), authority_address
        )
        if value in str(response):
            logger.debug("%s have the expected value!", authority_name)
        else:
            if retrys[authority_address] < retry:
                logger.info(
                  "%s don't have the expected value, will have to retry (%d / %d)", 
                  authority_name, retrys[authority_address], retry
                )
                authorities.append((authority_name, authority_address))
                sleep(sleep_delay)
            else:
                 logger.error(
                  "%s don't have the expected value, Max retry reached", 
                  authority_name
                )
    logger.info("All authoritative servers have the expected value.")

class Authenticator(dns_rfc2136.Authenticator):
    """DNS Authenticator using RFC 2136 Dynamic Updates and wait for DNS propagation.

    This Authenticator uses RFC 2136 Dynamic Updates to fulfill a dns-01 challenge.
    It also wait for DNS propagation before returning hand.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using BIND for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_retry: int = 6) -> None:
        super().add_parser_arguments(add, default_propagation_retry=6)

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'RFC 2136 Dynamic Updates and wait for DNS propagation.'

    def perform(self, achalls: List[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]: # pylint: disable=missing-function-docstring
        ret = self.perform(achalls)

        for achall in achalls:
            domain = achall.domain
            validation_domain_name = achall.validation_domain_name(domain)
            validation = achall.validation(achall.account_key)
            wait_dns(validation_domain_name, "TXT", validation, 
                     self.conf('propagation-retry'), 
                     self.conf('propagation-seconds')
                    )
        # We have waiting and retrying for all domains.
        return responses
