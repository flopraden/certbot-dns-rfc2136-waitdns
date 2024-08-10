"""Vault Let's Encrypt installer plugin."""

import logging

from typing import Any, Callable, cast, Optional, List
from time import sleep
import random

from acme import challenges
from certbot import achallenges, errors

import dns.message
import dns.resolver
import dns.query

from certbot_dns_rfc2136._internal import dns_rfc2136


logger = logging.getLogger(__name__)


def find_authority(qname:str):
    """Locate the autoritative name server for the given name using a stub
    resolver.
    """
    zone = dns.resolver.zone_for_name(qname)
    return [
        (ns.target, a.address)
        for ns in dns.resolver.resolve(zone, "NS")
        for a in dns.resolver.resolve(ns.target, "A")
    ]


def wait_dns(qname:str, rdtype:str, value:str, retry:int, sleep_delay:int, max_sleep_delay:int, exponential_backoff:bool, backoff_seconds:int) -> bool:
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
            if (retry < 0) or (retrys[authority_address] < retry):
                logger.info(
                  "%s don't have the expected value, will have to retry (%d / %d)", 
                  authority_name, retrys[authority_address], retry
                )
                authorities.append((authority_name, authority_address))
                delay = sleep_delay + random.uniform(0, 1)
                if exponential_backoff:
                    delay +=  (backoff_seconds * 2 **  retrys[authority_address])
                if delay > max_sleep_delay:
                    delay = max_sleep_delay
                logger.info("Waiting for %f seconds", delay)
                sleep(delay)
                retrys[authority_address] += 1
            else:
                 logger.error(
                  "%s don't have the expected value, Max retry reached", 
                  authority_name
                )
                 return False
    logger.info("All authoritative servers have the expected value.")
    return True
class Authenticator(dns_rfc2136.Authenticator):
    """DNS Authenticator using RFC 2136 Dynamic Updates and wait for DNS propagation.

    This Authenticator uses RFC 2136 Dynamic Updates to fulfill a dns-01 challenge.
    It also wait for DNS propagation before returning hand.
    """

    description = 'Obtain certificates using a DNS TXT record with RFC2136 Dynamic update and wait for propagation.'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        super().add_parser_arguments(add)
        add('propagation-retry',
             help='The number of retry for the propagation waiting.',
             default=6,
             type=int
        )
        add('exponential-backoff-retry',
             help='Enable exponential backoff when retrying for a server.',
             default=False,
             type=bool
        )
        add('exponential-backoff-seconds',
             help='Parameters in the exponential backoff in seconds : Using <exponential-backoff-seconds> * 2**(number of retries done).',
             default=600,
             type=int
        )
        add('max-delay-time',
             help='The number of maximum seconds to wait between each retry.',
             default=600,
             type=int
        )

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'RFC 2136 Dynamic Updates and wait for DNS propagation.'

    def perform(self, achalls: List[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]: # pylint: disable=missing-function-docstring
        responses = super().perform(achalls)
        retry = self.conf('propagation-retry')
        wait = self.conf('propagation-seconds')
        exponential_backoff = self.conf('exponential-backoff-retry')
        exponential_backoff_seconds = self.conf('exponential-backoff-seconds')
        max_delay_time = self.conf('max-delay-time')
        for achall in achalls:
            domain = achall.domain
            validation_domain_name = achall.validation_domain_name(domain)
            validation = achall.validation(achall.account_key)
            if not wait_dns(validation_domain_name, "TXT", validation, 
                     retry, 
                     wait, max_delay_time,
                     exponential_backoff, exponential_backoff_seconds
                    ):
                raise errors.PluginError('The DNS update could not update all DNS server. See log for more information.')
        # We have waiting and retrying for all domains.
        return responses
