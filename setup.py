from setuptools import setup
from setuptools import find_packages


setup(
    name='certbot-dns-rfc2136-waitdns',  # Required
    version='0.1.0',  # Required
    description='Certbot plugin for Authenticate with DNS RFC2136 and wait for propagation',
    url='https://github.com/flopraden/certbot-dns-rfc2136-waitdns',  # Optional


    author='Praden Florian',  # Optional
    author_email='<none@gmail.com>',  # Optional

    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Plugins',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities'
    ],

    packages=find_packages(),  # Required
    include_package_data=True,

    install_requires=[
        'dns'
        'certbot_dns_rfc2136'
    ],

    entry_points={
        'certbot.plugins': [
            'certbot_dns_rfc2136_waitdns = certbot_dns_rfc2136_waitdns._internal.dns_rfc2136_waitdns:Authenticator',
        ],
    }
)
