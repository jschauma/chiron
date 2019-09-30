"""Chiron support for Zulip"""

from __future__ import print_function, unicode_literals

import zulip

import chiron

class ZulipMessage(chiron.Message):
    """Chiron Zulip protocol class"""
    def __init__(self, client, zulip_msg):
        self._client = client
        self._zulip = zulip_msg

    def body(self):
        return self._zulip['content']

    def cls(self):
        return self._zulip['display_recipient']

    def instance(self):
        return self._zulip['subject']

    def sender(self):
        return self._zulip['sender_email']

    def recipient(self):
        return "(ignored)"

    def is_personal(self):
        return self._zulip['type'] == 'private'

    def send_reply(self, messages):
        zulip_msg = self._zulip
        reply = {}

        if self.is_personal():
            reply['type'] = 'private'
            reply['to'] = [r['email'] for r in zulip_msg['display_recipient']]
        else:
            reply['type'] = 'stream'
            reply['to'] = zulip_msg['display_recipient']
            reply['subject'] = zulip_msg['subject']

        if messages:
            body = '\n'.join(["[%s](%s)" % (m, url) for m, url in messages])
        else:
            body = "No ticket number found in message."
        reply['content'] = body

        if messages or self.is_personal():
            print("  ->", self._client.send_message(reply))

    @classmethod
    def build_processor(cls, match_engine, client):
        """Build message callback"""
        def process(zulip_msg):
            """Zulip message callback"""
            msg = cls(client, zulip_msg)
            if '-bot' in msg.sender():
                print("Skipping message from %s:" % (msg.sender(), ))
                msg.log_arrival()
            else:
                match_engine.process(msg)
        return process

    @classmethod
    def main(cls, match_engine, options):
        """Main function for running Chiron with Zulip"""
        # zuliprc defaults to None, as does config_file
        # In both cases, this is interpreted as ~/.zuliprc
        client = zulip.Client(config_file=options.zuliprc)
        print("Listening...")
        message_callback = cls.build_processor(match_engine, client)
        client.call_on_each_message(message_callback)

def main(match_engine, options):
    """Main function for running Chiron with Zulip"""
    ZulipMessage.main(match_engine, options)
