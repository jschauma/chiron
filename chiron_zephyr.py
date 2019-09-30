"""Chiron support for Zephyr"""

from __future__ import print_function, unicode_literals

import re
import sys

import chiron

try:
    import zephyr
except ImportError:
    import site
    site.addsitedir('/mit/broder/lib/python%s/site-packages' % sys.version[:3])
    import zephyr

DEFAULT_REALM = 'ATHENA.MIT.EDU'

# Used for handling CC's
def strip_default_realm(principal):
    """Remove the default realm from a principal"""
    if '@' in principal:
        user, domain = principal.split('@')
        if domain == DEFAULT_REALM:
            return user
    return principal

def add_default_realm(principal):
    """Add the default realm to a principal"""
    if '@' in principal:
        return principal
    return "%s@%s" % (principal, DEFAULT_REALM, )

def zephyr_setup(classes, personals=True):
    """Connect and subscribe to zephyr"""
    zephyr.init()
    subs = zephyr.Subscriptions()
    for cls in classes:
        subs.add((cls, '*', '*'))
    if personals:
        subs.add(('message', '*', '%me%'))
    else:
        # The zephyrd's give you personals by default
        # Unfortunately, the subscriptions object doesn't reflect this
        # To get rid of them, explicitly *sub* (so the subscription object
        # knows), and then unsub.
        default_personals = ('message', 'personal', '%me%')
        subs.add(default_personals)
        subs.remove(default_personals)

CC_RE = re.compile(r"CC:(?P<recips>( [a-z./@]+)+) *$", re.MULTILINE)

class ZephyrMessage(chiron.Message):
    """Chiron Zephyr protocol class"""
    def __init__(self, zgram):
        self._zgram = zgram

    def body(self):
        fields = self._zgram.fields
        body = fields[1] if len(fields) > 1 else fields[0]
        if not isinstance(body, unicode): #pylint:disable=undefined-variable
            body = body.decode('utf8')
        return body

    def cls(self):
        return self._zgram.cls

    def instance(self):
        return self._zgram.instance

    def sender(self):
        return self._zgram.sender

    def recipient(self):
        return self._zgram.recipient

    def is_personal(self):
        return bool(self._zgram.recipient)

    def _prep_zgram(self):
        zgram = self._zgram
        zreply = zephyr.ZNotice()
        zreply.cls = zgram.cls
        zreply.instance = zgram.instance
        #zreply.format = "http://zephyr.1ts.org/wiki/df"
        # The following default format will cause messages not to be mirrored to MIT Zulip.
        #zreply.format = "Zephyr error: See http://zephyr.1ts.org/wiki/df"
        zreply.opcode = 'auto'
        return zreply

    def _compute_recipients(self, zreply):
        zgram = self._zgram
        recipients = set()
        if self.is_personal():
            recipients.add(zgram.sender)
            cc_match = CC_RE.match(self.body())
            if cc_match:
                cc_recips = cc_match.group('recips').split(' ')
                for cc_recip in cc_recips:
                    if cc_recip and 'chiron' not in cc_recip:
                        recipients.add(add_default_realm(str(cc_recip.strip())))
            zreply.sender = zgram.recipient
        else:
            recipients.add(zgram.recipient)
        return recipients

    def _send_zgrams(self, messages, zreply, recipients):
        if messages:
            body = '\n'.join(["%s ( %s )" % (m, url) for m, url in messages])
        else:
            url = "https://github.com/sipb/chiron"
            body = "No ticket number found in message."
        if len(recipients) > 1:
            cc_line = " ".join([strip_default_realm(r) for r in recipients])
            body = "CC: %s\n%s" % (cc_line, body)
        zreply.fields = [" "+url+" ", body]
        print('  -> Reply to: %s (original message was to "%s")' %
              (recipients, self._zgram.recipient, ))
        if messages or self.is_personal():
            for recipient in recipients:
                zreply.recipient = recipient
                zreply.send()

    def send_reply(self, messages):
        zreply = self._prep_zgram()
        recipients = self._compute_recipients(zreply)
        self._send_zgrams(messages, zreply, recipients)

    @classmethod
    def main(cls, match_engine, options): #pylint:disable=unused-argument
        """Main function for running Chiron with Zephyr"""
        zephyr_setup(match_engine.classes, not match_engine.ignore_personals)
        print("Listening...")
        while True:
            zgram = zephyr.receive(True)
            if not zgram:
                continue
            if zgram.opcode.lower() in ('auto', 'ping'):
                continue
            msg = cls(zgram)
            match_engine.process(msg)

def main(match_engine, options):
    """Main function for running Chiron with Zephyr"""
    ZephyrMessage.main(match_engine, options)
