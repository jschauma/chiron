#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import urllib
from lxml import etree
import time
import datetime
import sys
from random import choice
import os
import json
import csv

seen_timeout = 5 * 60
parser = etree.HTMLParser(encoding='UTF-8')

class Message(object):
    def log_arrival(self, ):
        print '%s: -c %s -i "%s": %s -> %s' % (
            datetime.datetime.now(),
            self.cls(), self.instance(),
            self.sender(), self.recipient(),
        )

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
    def bugzilla_fetcher(ticket):
        u = '%s/show_bug.cgi?id=%s' % (url, ticket)
        f = urllib.urlopen(u)
        t = etree.parse(f, parser)
        title = t.xpath('string(//span[@id="short_desc_nonedit_display"])')
        if title:
            return u, title
        else:
            return u, None
    return bugzilla_fetcher

def fetch_trac(url):
    def trac_fetcher(ticket):
        u = '%s/ticket/%s' % (url, ticket)
        f = urllib.urlopen(u + '?format=csv')
        if f.getcode() == 200:
            d = dict(zip(*csv.reader(f)))
            return u, unicode(d['summary'], 'utf-8')
        else:
            return u, None
    return trac_fetcher

def fetch_github(user, repo, ):
    def fetch(ticket):
        u = 'https://api.github.com/repos/%s/%s/issues/%s' % (user, repo, ticket, )
        f = urllib.urlopen(u)
        j = json.load(f)
        try:
            return j['html_url'], j['title']
        except KeyError:
            return u, None
    return fetch

# Project-specific fetchers

def fetch_rfc(number):
    u = "https://tools.ietf.org/html/rfc%s" % (number, )
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    title = t.xpath('string(//meta[@name="DC.Title"]/@content)')
    return u, (title or None)

fetch_cve_rhbz = fetch_bugzilla("https://bugzilla.redhat.com")
def fetch_cve(ticket):
    # Try fetching from RHBZ first, since it tends to be better
    url, title = fetch_cve_rhbz(ticket)
    print "RHBZ url='%s' title='%s'" % (url, title)
    if title:
        return url, "[RHBZ] " + title

    u = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=%s' % ticket
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    title = t.xpath('string(//tr[th="Description"]/following::tr[1])')
    if title:
        return u, "\n" + title.strip() + "\n"
    else:
        return u, None

def fetch_scripts_faq(ticket):
    u = 'http://scripts.mit.edu/faq/%s' % ticket
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    title = t.xpath('string(//h3[@class="storytitle"])')
    if title:
        return u, title
    else:
        return u, None

def fetch_launchpad(ticket):
    u = 'http://api.launchpad.net/1.0/bugs/%s' % ticket
    f = urllib.urlopen(u)
    j = json.load(f)
    try:
        return j['web_link'], j['title']
    except KeyError:
        return u, None

def fetch_debbugs(url):
    def debbugs_fetcher(ticket):
        u = '%s/cgi-bin/bugreport.cgi?bug=%s' % (url, ticket)
        f = urllib.urlopen(u)
        t = etree.parse(f, parser)
        title = t.xpath('normalize-space(//h1/child::text()[2])')
        if title:
            return u, title
        else:
            return u, None
    return debbugs_fetcher

def fetch_dsa(number):
    tu = "https://security-tracker.debian.org/tracker/%s" % (number, )
    tf = urllib.urlopen(tu)
    tt = etree.parse(tf, parser)
    dsa_urls = tt.xpath('//a[text()="Debian"]/@href[starts-with(.,"http://www.debian.org/security/")]')
    title = tt.xpath('string(//tr[td/b="Description"]/td[2])') or None
    print "    -> DSA URLs in page: %s" % (dsa_urls, )
    if dsa_urls:
        dsa_url = dsa_urls[0]
    else:
        dsa_url = tu
    return dsa_url, title


def fetch_pokemon(ticket):
    u = 'http://bulbapedia.bulbagarden.net/wiki/List_of_Pok%C3%A9mon_by_National_Pok%C3%A9dex_number'
    f = urllib.urlopen(u + '?action=raw')
    for line in f:
        if line[0:7] == '{{rdex|':
            (id, name) = line.split('|')[2:4]
            try:
                if int(id) == int(ticket):
                    return u, "%s (%s)" % (name, ", ".join(line.split('}')[0].split('|')[5:]))
            except ValueError:
                pass
    return u, None

def fetch_mit_class(ticket):
    u = 'http://student.mit.edu/catalog/search.cgi?search=%s' % (ticket, )
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    title = t.xpath('string(//h3)')
    if title:
        return u, title
    else:
        return u, None

def fetch_whats(whats):
    u = "http://stuff.mit.edu/cgi/whats.cgi?%s" % (whats, )
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    title = t.xpath('string(//dl/dd)')
    if title:
        title = title.strip()
    return u, (title or None)

def undebathena_fun():
    u = 'http://debathena.mit.edu/trac/wiki/PackageNamesWeDidntUse'
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    package = choice(t.xpath('id("content")//li')).text.strip()
    dir = choice(['/etc', '/bin', '/usr/bin', '/sbin', '/usr/sbin',
                  '/dev/mapper', '/etc/default', '/var/run'])
    file = choice(os.listdir(dir))
    return u, "%s should divert %s/%s" % (package, dir, file)

def fetch_bible(verse):
    u = 'http://www.esvapi.org/v2/rest/passageQuery?key=IP&passage=%s&output-format=plain-text' % (urllib.quote_plus(verse), )
    bible_text = urllib.urlopen(u).read()
    copyright = "(From The Holy Bible, English Standard Version. See http://www.crosswaybibles.org and http://www.esvapi.org/.)"
    text = "\n%s\n%s" % (bible_text, copyright, )
    return u, text

def fetch_xkcd(comic):
    u = 'http://xkcd.com/%s/' % (comic, )
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    title = t.xpath('string(//title)')
    if title and f.getcode() == 200:
        return u, title
    else:
        return u, None

def fetch_unicode(codepoint):
    u = 'http://www.fileformat.info/info/unicode/char/%s/index.htm' % (codepoint, )
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    title = t.xpath('string(//title)')
    if title and f.getcode() == 200:
        return u, title + ': ' + unichr(int(codepoint, 16))
    else:
        return u, None

def fetch_unicode_char(character):
    codepoint = format(ord(character), 'x')
    u = 'http://www.fileformat.info/info/unicode/char/%s/index.htm' % (codepoint, )
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    title = t.xpath('string(//title)')
    if title and f.getcode() == 200:
        return u, title
    else:
        return u, "U+%s" % (codepoint, )

def fetch_airport(code):
    u = 'http://www.gcmap.com/airport/%s' % (code, )
    f = urllib.urlopen(u)
    t = etree.parse(f, parser)
    place = t.xpath('string(//meta[@name="geo.placename"]/@content)')
    name = t.xpath('string(//td[@class="fn org"])')
    if place and f.getcode() == 200:
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
                        tickets = filter(lambda ticket1: not subspan(ticket1[3], span), tickets)
                        # Add this matcher
                        tickets.append((tracker, self.fetchers[tracker], match.group(1), span))
        return tickets

    def process(self, msg, ):
        msg.log_arrival()
        if self.ignore_personals and msg.is_personal():
            print "  -> ignoring personal"
            return
        tickets = self.find_ticket_info(msg)
        messages = format_tickets(self.last_seen, msg, tickets)
        msg.send_reply(messages)

def format_tickets(last_seen, msg, tickets):
    messages = []
    for tracker, fetcher, ticket, span in tickets:
        print "  -> Found ticket: %s, %s" % (tracker, ticket, )
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
