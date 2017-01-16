#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import re
from lxml import etree
import time
import datetime
import sys
from random import choice
import requests
import os
import json
import csv

try:
    unichr
except NameError as e: # not available in Py3
    unichr = chr

seen_timeout = 5 * 60
parser = etree.HTMLParser(encoding='UTF-8')

def fetch_and_parse_xml(url):
    r = requests.get(url, stream=True)
    t = etree.fromstring(r.content, parser)
    return t,r

class Message(object):
    def log_arrival(self, ):
        print('%s: -c %s -i "%s": %s -> %s' % (
            datetime.datetime.now(),
            self.cls(), self.instance(),
            self.sender(), self.recipient(),
        ))

    def body(self): raise NotImplementedError

    def cls(self): raise NotImplementedError

    def instance(self): return ""

    def sender(self): raise NotImplementedError

    def recipient(self): raise NotImplementedError

    def is_personal(self): raise NotImplementedError

    def context(self, ):
        # We have default fetchers for some classes. This adds two more ways
        # to trigger default fetchers behavior:
        # - test classes (for easier testing of defaults)
        # - instanced personals (to facilitate looking up many tickets for one project)
        if "-test" in self.cls() or self.is_personal():
            return self.instance()
        else:
            return self.cls()

    def send_reply(self, messages): raise NotImplementedError

def build_matcher(regex, flags=0):
    r = re.compile(regex, flags)
    def match(msg):
        return r.finditer(msg.body())
    return match


#####################
# Code for Fetchers #
#####################

# Generic fetchers (parametrizable by site)

def fetch_bugzilla(url):
    """
    Return a fetcher for a bugzilla instance

    >>> fetch_bugzilla("https://bugzilla.redhat.com")("123456")
    (u'https://bugzilla.redhat.com/show_bug.cgi?id=123456', 'System with Syntax - S635MP motherboard will not install')
    """
    def bugzilla_fetcher(ticket):
        u = '%s/show_bug.cgi?id=%s' % (url, ticket)
        t,r = fetch_and_parse_xml(u)
        title = t.xpath('string(//span[@id="short_desc_nonedit_display"])')
        if title:
            return u, title
        else:
            return u, None
    return bugzilla_fetcher

def fetch_trac(url):
    """
    Return a fetcher for a Trac instance

    >>> fetch_trac("https://debathena.mit.edu/trac")("123")
    (u'https://debathena.mit.edu/trac/ticket/123', 'debathena-ssl-certificates should include a CRL')
    """
    def trac_fetcher(ticket):
        u = '%s/ticket/%s' % (url, ticket)
        r = requests.get(u + '?format=csv')
        if r.status_code == 200:
            reader = csv.DictReader(r.text.split('\n'))
            row = next(reader)
            return u, row['summary']
        else:
            return u, None
    return trac_fetcher

def fetch_github(user, repo, ):
    """
    Return a fetcher for a Github instance

    >>> fetch_github("sipb", "chiron")("2")
    (u'https://github.com/sipb/chiron/issues/2', u'Teach debothena about its bugtracker')
    """
    def fetch(ticket):
        u = 'https://api.github.com/repos/%s/%s/issues/%s' % (user, repo, ticket, )
        r = requests.get(u)
        try:
            return r.json()['html_url'], r.json()['title']
        except KeyError:
            return u, None
    return fetch

# Project-specific fetchers

def fetch_rfc(number):
    """
    RFC fetcher

    >>> fetch_rfc("1234")
    (u'https://tools.ietf.org/html/rfc1234', 'Tunneling IPX traffic through IP networks')
    """
    u = "https://tools.ietf.org/html/rfc%s" % (number, )
    t,r = fetch_and_parse_xml(u)
    title = t.xpath('string(//meta[@name="DC.Title"]/@content)')
    return u, (title or None)

fetch_cve_rhbz = fetch_bugzilla("https://bugzilla.redhat.com")
def fetch_cve(ticket):
    """
    CVE fetcher

    >>> fetch_cve("CVE-2015-1234")
    RHBZ url='https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2015-1234' title='CVE-2015-1234 chromium-browser: buffer overflow via race condition in GPU'
    (u'https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2015-1234', u'[RHBZ] CVE-2015-1234 chromium-browser: buffer overflow via race condition in GPU')
    >>> fetch_cve("CVE-1999-0012")
    RHBZ url='https://bugzilla.redhat.com/show_bug.cgi?id=CVE-1999-0012' title='None'
    (u'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0012', u'\\nSome web servers under Microsoft Windows allow remote attackers\\nto bypass access restrictions for files with long file names.\\n')
    >>> fetch_cve("CVE-1999-9000")
    RHBZ url='https://bugzilla.redhat.com/show_bug.cgi?id=CVE-1999-9000' title='None'
    (u'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-9000', None)
    """
    # Try fetching from RHBZ first, since it tends to be better
    url, title = fetch_cve_rhbz(ticket)
    print("RHBZ url='%s' title='%s'" % (url, title))
    if title:
        return url, "[RHBZ] " + title

    u = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=%s' % ticket
    t,r = fetch_and_parse_xml(u)
    title = t.xpath('string(//tr[th="Description"]/following::tr[1])')
    if title:
        return u, "\n" + title.strip() + "\n"
    else:
        return u, None

def fetch_scripts_faq(ticket):
    """
    scripts.mit.edu FAQ fetcher

    >>> fetch_scripts_faq("136")
    (u'http://scripts.mit.edu/faq/136', u'Is scripts.mit.edu appropriate for my\\xa0site?')
    """
    u = 'http://scripts.mit.edu/faq/%s' % ticket
    t,r = fetch_and_parse_xml(u)
    title = t.xpath('string(//h3[@class="storytitle"])')
    if title:
        return u, title
    else:
        return u, None

def fetch_launchpad(ticket):
    """
    Launchpad fetcher

    >>> fetch_launchpad("123456")
    (u'https://bugs.launchpad.net/bugs/123456', u'podcast crashes amarok')
    """
    u = 'http://api.launchpad.net/1.0/bugs/%s' % ticket
    r = requests.get(u)
    try:
        return r.json()['web_link'], r.json()['title']
    except KeyError:
        return u, None

def fetch_debbugs(url):
    """
    Debbugs (Debian bugtracker) fetcher

    >>> fetch_debbugs("https://bugs.debian.org")("123456")
    (u'https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=123456', 'ITP: eazel-engine -- Crux theme for GTK+')
    """
    def debbugs_fetcher(ticket):
        u = '%s/cgi-bin/bugreport.cgi?bug=%s' % (url, ticket)
        t,r = fetch_and_parse_xml(u)
        title = t.xpath('normalize-space(//h1/child::text()[2])')
        if title:
            return u, title
        else:
            return u, None
    return debbugs_fetcher

def fetch_dsa(number):
    """
    Debian Security Advisories fetcher

    >>> fetch_dsa("DSA-1234")
        -> DSA URLs in page: []
    (u'https://security-tracker.debian.org/tracker/DSA-1234', 'ruby1.6')
    """
    tu = "https://security-tracker.debian.org/tracker/%s" % (number, )
    tt,r = fetch_and_parse_xml(tu)
    dsa_urls = tt.xpath('//a[text()="Debian"]/@href[starts-with(.,"http://www.debian.org/security/")]')
    title = tt.xpath('string(//tr[td/b="Description"]/td[2])') or None
    print("    -> DSA URLs in page: %s" % (dsa_urls, ))
    if dsa_urls:
        dsa_url = dsa_urls[0]
    else:
        dsa_url = tu
    return dsa_url, title


def fetch_pokemon(ticket):
    """
    Pokemon fetcher (by Pokedex number)

    >>> fetch_pokemon("123")
    (u'http://bulbapedia.bulbagarden.net/wiki/List_of_Pok%C3%A9mon_by_National_Pok%C3%A9dex_number', u'Scyther (Bug, Flying)')
    """
    u = 'http://bulbapedia.bulbagarden.net/wiki/List_of_Pok%C3%A9mon_by_National_Pok%C3%A9dex_number'
    r = requests.get(u + '?action=raw')
    for line in r.text.split('\n'):
        if line[0:7] == '{{rdex|':
            (id, name) = line.split('|')[2:4]
            try:
                if int(id) == int(ticket):
                    return u, "%s (%s)" % (name, ", ".join(line.split('}')[0].split('|')[5:]))
            except ValueError:
                pass
    return u, None

def fetch_mit_class(ticket):
    """
    MIT class fetcher

    >>> fetch_mit_class("6.828")
    (u'http://student.mit.edu/catalog/search.cgi?search=6.828', '6.828 Operating System Engineering')
    """
    u = 'http://student.mit.edu/catalog/search.cgi?search=%s' % (ticket, )
    t,r = fetch_and_parse_xml(u)
    title = t.xpath('string(//h3)')
    if title:
        return u, title.strip()
    else:
        return u, None

def fetch_whats(whats):
    """
    whats fetcher (MIT SIPB acronym database)

    >>> fetch_whats("SIPB")
    (u'https://stuff.mit.edu/cgi/whats.cgi?SIPB', 'Student Information Processing Board')
    """
    u = "https://stuff.mit.edu/cgi/whats.cgi?%s" % (whats, )
    t,r = fetch_and_parse_xml(u)
    title = t.xpath('string(//dl/dd)')
    if title:
        title = title.strip()
    return u, (title or None)

def undebathena_fun():
    u = 'http://debathena.mit.edu/trac/wiki/PackageNamesWeDidntUse'
    t,r = fetch_and_parse_xml(u)
    package = choice(t.xpath('id("content")//li')).text.strip()
    dir = choice(['/etc', '/bin', '/usr/bin', '/sbin', '/usr/sbin',
                  '/dev/mapper', '/etc/default', '/var/run'])
    file = choice(os.listdir(dir))
    return u, "%s should divert %s/%s" % (package, dir, file)

def fetch_bible(verse):
    r"""
    Bible fetcher

    >>> fetch_bible("John 4:8")
    (u'http://www.esvapi.org/v2/rest/passageQuery?key=IP&passage=John+4%3A8&output-format=plain-text', u'\n=======================================================\nJohn 4:8\n   [8](For his disciples had gone away into the city to buy food.) (ESV)\n(From The Holy Bible, English Standard Version. See http://www.crosswaybibles.org and http://www.esvapi.org/.)')
    """
    u = 'http://www.esvapi.org/v2/rest/passageQuery'
    params = (('key','IP'), ('passage',verse), ('output-format','plain-text'))
    r = requests.get(u, params=params)
    copyright = "(From The Holy Bible, English Standard Version. See http://www.crosswaybibles.org and http://www.esvapi.org/.)"
    text = "\n%s\n%s" % (r.text, copyright, )
    return r.url, text

def fetch_xkcd(comic):
    """
    XKCD fetcher

    >>> fetch_xkcd("123")
    (u'http://xkcd.com/123/', 'xkcd: Centrifugal Force')
    """
    u = 'http://xkcd.com/%s/' % (comic, )
    t,r = fetch_and_parse_xml(u)
    title = t.xpath('string(//title)')
    if title and r.status_code == 200:
        return u, title
    else:
        return u, None

def fetch_unicode(codepoint):
    """
    Unicode fetcher (number->char)

    This would work with a browser, but we seem to be blocked by Cloudflare
    now, so Chiron's Unicode support seems to be broken. So, uh, test that it
    hasn't resumed working.

    >>> fetch_unicode("2603")
    Unicode: 'Unicode Character 'SNOWMAN' (U+2603)' '200'
    (u'https://www.fileformat.info/info/unicode/char/2603/index.htm', u"Unicode Character 'SNOWMAN' (U+2603): \\u2603")
    """
    u = 'https://www.fileformat.info/info/unicode/char/%s/index.htm' % (codepoint, )
    t,r = fetch_and_parse_xml(u)
    title = t.xpath('string(//title)')
    print("Unicode: '%s' '%s'" % (title, r.status_code))
    if title and r.status_code == 200:
        return u, title + ': ' + unichr(int(codepoint, 16))
    else:
        return u, None

def fetch_unicode_char(character):
    """
    Unicode fetcher (char->number)

    >>> fetch_unicode_char("\u1234")
    (u'https://www.fileformat.info/info/unicode/char/1234/index.htm', "Unicode Character 'ETHIOPIC SYLLABLE SEE' (U+1234)")
    """
    codepoint = format(ord(character), 'x')
    u = 'https://www.fileformat.info/info/unicode/char/%s/index.htm' % (codepoint, )
    t,r = fetch_and_parse_xml(u)
    title = t.xpath('string(//title)')
    if title and r.status_code == 200:
        return u, title
    else:
        return u, "U+%s" % (codepoint, )

def fetch_airport(code):
    """
    Airport fetcher (code->location)

    >>> fetch_airport("BOS")
    (u'http://www.gcmap.com/airport/BOS', u'Boston, Massachusetts, United States (General Edward Lawrence Logan International Airport)')
    """
    u = 'http://www.gcmap.com/airport/%s' % (code, )
    t,r = fetch_and_parse_xml(u)
    place = t.xpath('string(//meta[@name="geo.placename"]/@content)')
    name = t.xpath('string(//td[@class="fn org"])')
    if place and r.status_code == 200:
        if name:
            title = "%s (%s)" % (place, name, )
        else:
            title = place
        return u, title
    else:
        return u, None


# Special constant-text fetchers

def deal_with_assassin(ticket):
    return ("NO COMBOS OVER ZEPHYR",
"""DO @b(NOT) ASK FOR OR SEND THE OFFICE COMBO
OVER ZEPHYR, EVEN PERSONAL ZEPHYR.
Instead, look in /mit/assassin/Office. If you don't have access,
ask to be added.""")

def invoke_science(ticket):
    return ("SCIENCE!",
"""
  ____   ____ ___ _____ _   _  ____ _____
 / ___| / ___|_ _| ____| \ | |/ ___| ____|
 \___ \| |    | ||  _| |  \| | |   |  _|
  ___) | |___ | || |___| |\  | |___| |___
 |____/ \____|___|_____|_| \_|\____|_____|
""")

def invoke_debothena(ticket):
    return (ticket,
u"""
╺┳┓┏━╸┏┓ ┏━┓╺┳╸╻ ╻┏━╸┏┓╻┏━┓
 ┃┃┣╸ ┣┻┓┃ ┃ ┃ ┣━┫┣╸ ┃┗┫┣━┫
╺┻┛┗━╸┗━┛┗━┛ ╹ ╹ ╹┗━╸╹ ╹╹ ╹
""")


#########################################
# Declarations of MATCHERS and FETCHERS #
#########################################

def subspan(arg1, arg2):
    """Return whether the (x,y) range indicated by arg1 is entirely contained in arg2"""
    a,b=arg1
    c,d=arg2
    return cmp(a, c) - cmp(b, d) >= 1

class MatchEngine(object):
    def __init__(self, ):
        self.classes = []
        self.fetchers = {}
        self.matchers = []
        self.last_seen = {}
        self.ignore_personals = False

    def add_classes(self, classes):
        self.classes.extend(classes)

    def add_fetchers(self, fetchers):
        for name, fetcher in fetchers.items():
            assert name not in self.fetchers
            self.fetchers[name] = fetcher

    def add_matcher(self, fetcher, regexp, cond=False, classes=True, flags=re.I, ):
        assert fetcher in self.fetchers
        if cond:
            pass
        elif classes == True:
            cond = lambda m: True
        else:
            cond = lambda m: (len([cls for cls in classes if cls in m.context()]) > 0)
        self.matchers.append((fetcher, [build_matcher(regexp, flags)], cond))

    def add_trac(self, name, url, classes=None):
        lname = name.lower()
        if classes is None:
            classes = [lname]
        assert name not in self.fetchers
        self.fetchers[name] = fetch_trac(url)
        self.add_matcher(name, r'\b%s[-\s:]*#([0-9]{1,5})\b' % (lname, ))
        self.add_matcher(name, r'\btrac[-\s:]*#([0-9]{1,5})\b', classes=classes)
        # The "-Ubuntu" bit ignores any "uname -a" snippets that might get zephyred
        self.add_matcher(name, r'#([0-9]{2,5})\b(?!-Ubuntu)', classes=classes)

    def find_ticket_info(self, msg):
        tickets = []
        for tracker, ms, cond in self.matchers:
            if cond(msg):
                for m in ms:
                    for match in m(msg):
                        span = match.span()
                        # If the text matched by this matcher is a subset of
                        # that matched for by any other matcher, skip this one
                        if any(subspan(span, span1) for tracker1, fetcher1, t1, span1 in tickets):
                            continue
                        # Remove from tickets any whose text is a subset of
                        # this one's matched text.
                        tickets = list(filter(lambda ticket1: not subspan(ticket1[3], span), tickets))
                        # Add this matcher
                        tickets.append((tracker, self.fetchers[tracker], match.group(1), span))
        return tickets

    def process(self, msg, ):
        msg.log_arrival()
        if self.ignore_personals and msg.is_personal():
            print("  -> ignoring personal")
            return
        tickets = self.find_ticket_info(msg)
        messages = format_tickets(self.last_seen, msg, tickets)
        msg.send_reply(messages)

def format_tickets(last_seen, msg, tickets):
    messages = []
    for tracker, fetcher, ticket, span in tickets:
        print("  -> Found ticket: %s, %s" % (tracker, ticket, ))
        old_enough = (last_seen.get((tracker, ticket, msg.cls()), 0) < time.time() - seen_timeout)
        # for personals, don't bother tracking age
        if old_enough or msg.is_personal():
            if msg.cls()[:2] == 'un':
                u, t = undebathena_fun()
            else:
                u, t = fetcher(ticket)
            if not t:
                t = 'Unable to identify ticket %s' % ticket
            message = '%s ticket %s: %s' % (tracker, ticket, t)
            messages.append((message, u))
            last_seen[(tracker, ticket, msg.cls())] = time.time()
    return messages

if __name__ == '__main__':
    import doctest
    doctest.testmod()
