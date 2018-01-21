#!/usr/bin/env python
from __future__ import print_function, unicode_literals

import unittest

import chiron

class TestMessage(chiron.Message):
    def __init__(self, body, cls, is_personal):
        self._body = body
        self._cls = cls
        self._is_personal = is_personal
        self._replies = []

    def body(self): return self._body
    def cls(self): return self._cls
    def instance(self): return "(instance)"
    def sender(self): return "(sender)"
    def recipient(self): return "(recipient)"
    def is_personal(self): return self._is_personal

    def send_reply(self, messages):
        self._replies.append(messages)

def sample_fetcher(base):
    def fetcher(ticket):
        u = "https://example.com/%s?id=%s" % (base, ticket, )
        if ticket == "KNOWN":
            return (u, "found %s ticket" % (base, ))
        elif ticket == "UNKNOWN":
            return (u, None)
        else:
            if '.' in ticket: ticket = ticket.partition('.')[2]
            i = int(ticket)
            if i % 2 == 0: title = "even%deven" % (i, )
            else: title = None
            return (u, title)
    return fetcher

class TestEngine(unittest.TestCase):
    def setUp(self):
        self.engine = chiron.MatchEngine()
        self.engine.add_fetchers({
            'Sample': sample_fetcher('ticket'),
            'Other': sample_fetcher('other'),
            'RFC': sample_fetcher('rfc'),
            'Launchpad': sample_fetcher('rfc'),
            'MIT Class': sample_fetcher('mit'),
            'Scripts FAQ': sample_fetcher('faq'),
        })
        self.engine.add_matcher('RFC',         r'\bRFC[-\s:]*#?([0-9]{2,5})\b')
        self.engine.add_matcher('Launchpad',   r'\blp[-\s:]*#([0-9]{4,8})\b')
        self.engine.add_matcher('MIT Class',   r'class\s([0-9a-z]{1,3}[.][0-9a-z]{1,4})\b')
        self.engine.add_matcher('MIT Class',   r'([0-9a-z]{1,3}[.][0-9]{1,4})\b', cond=lambda m: m.is_personal())
        self.engine.add_matcher('Scripts FAQ', r'\bscripts\sfaq[-\s:]*#([0-9]{1,5})\b')
        self.engine.add_matcher('Scripts FAQ', r'\bfaq[-\s:]*#([0-9]{1,5})\b', classes=['scripts'])

    def assertReply(self, body, cls, is_personal, reply):
        msg = TestMessage(body, cls, is_personal)
        self.engine.process(msg)
        if reply is None:
            self.assertEqual(msg._replies, [])
        else:
            self.assertEqual(msg._replies, [reply])

    def test_engine(self):
        common_msg = "foo bar baz 6.123 quux\nClass 6.124 Scripts FAQ #14 FAQ #15"
        self.assertReply(common_msg, '', True, [
            ('MIT Class ticket 6.124: even124even', 'https://example.com/mit?id=6.124'),
            ('MIT Class ticket 6.123: Unable to identify ticket 6.123', 'https://example.com/mit?id=6.123'),
            ('Scripts FAQ ticket 14: even14even', 'https://example.com/faq?id=14'),
        ])

        # Reply warns about no ticket
        self.assertReply("foo bar baz", '', True, [])

        # Same behavior as non-personal -- "no ticket found" is up to message type
        self.assertReply("foo bar baz", 'foo', False, [])

        # 6.123 won't fire, because it's personals-only; others will
        self.assertReply(common_msg, 'foo', False, [
            ('MIT Class ticket 6.124: even124even', 'https://example.com/mit?id=6.124'),
            ('Scripts FAQ ticket 14: even14even', 'https://example.com/faq?id=14'),
        ])

        # Nothing fires, because too soon
        self.assertReply("foo bar baz 6.123 quux\nClass 6.124 Scripts FAQ #14", 'foo', False, [])

        # TODO: properly mock time, and verify that it *does* respond again after five minutes

        # Different class, so everything fires, plus FAQ #15
        self.assertReply(common_msg, 'scripts', False, [
            ('MIT Class ticket 6.124: even124even', 'https://example.com/mit?id=6.124'),
            ('Scripts FAQ ticket 14: even14even', 'https://example.com/faq?id=14'),
            ('Scripts FAQ ticket 15: Unable to identify ticket 15', 'https://example.com/faq?id=15'),
        ])

if __name__ == '__main__':
    unittest.main()
