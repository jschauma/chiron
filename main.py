#!/usr/bin/env python
from optparse import OptionParser

import chiron

def init_match_engine():
    match_engine = chiron.MatchEngine()
    add_default_fetchers(match_engine)
    add_default_matchers(match_engine)
    return match_engine

def add_default_classes(match_engine):
    match_engine.add_classes([
            'broder-test', 'geofft-test', 'adehnert-test',
            'linerva', 'debathena', 'undebathena', 'consult',
            'sipb', 'sipb-auto', 'scripts', 'barnowl', 'zephyr-dev', 'xvm', 'chiron', 'mirrors',
            'geofft', 'lizdenys', 'jdreed', 'axs', 'adehnert', 'achernya', 'leee', 'kcr', 'jesus', 'nelhage', 'csvoss', 'shulinye',
            'assassin',
            'shank',
            'remit', 'asa', 'esp',
        ])

def add_default_fetchers(match_engine):
    match_engine.add_fetchers({
        'RFC': chiron.fetch_rfc,
        'CVE': chiron.fetch_cve,
        'Launchpad': chiron.fetch_launchpad,
        'Debian': chiron.fetch_debbugs('http://bugs.debian.org'),
        'DSA': chiron.fetch_dsa,
        'Chiron': chiron.fetch_github('sipb', 'chiron'),
        'zcommit': chiron.fetch_github('sipb', 'zcommit'),
        'RHBZ': chiron.fetch_bugzilla('https://bugzilla.redhat.com'),
        'pag-screen': chiron.fetch_github('sipb', 'pag-screen'),
        'Mosh': chiron.fetch_github('keithw', 'mosh'),
        'Zulip': chiron.fetch_github('zulip', 'zulip'),
        'Scripts FAQ': chiron.fetch_scripts_faq,
        'ESP': chiron.fetch_github('learning-unlimited', 'ESP-Website'),
        'Pokedex': chiron.fetch_pokemon,
        'MIT Class': chiron.fetch_mit_class,
        'whats': chiron.fetch_whats,
        'Bible': chiron.fetch_bible,
        'XKCD': chiron.fetch_xkcd,
        'Unicode': chiron.fetch_unicode,
        'Unicode Character': chiron.fetch_unicode_char,
        'Airport': chiron.fetch_airport,
        'Assassin': chiron.deal_with_assassin,
        'SCIENCE': chiron.invoke_science,
        'Debothena Test': chiron.invoke_debothena,
        'Puzzle Editing': chiron.fetch_github('mysteryhunt', 'puzzle-editing'),
        })

def add_default_matchers(match_engine):
    match_engine.add_matcher('RFC',         r'\bRFC[-\s:]*#?([0-9]{2,5})\b')
    match_engine.add_matcher('CVE',         r'\b(CVE-[0-9]{4}-[0-9]{4,7})\b')
    match_engine.add_matcher('Launchpad',   r'\blp[-\s:]*#([0-9]{4,8})\b')
    match_engine.add_matcher('Debian',      r'\bdebian[-\s:]#([0-9]{4,6})\b')
    match_engine.add_matcher('DSA',         r'\b(DSA-[0-9-]{4,10})\b')
    match_engine.add_matcher('Chiron',      r'\bchiron[-\s:]*#([0-9]{1,5})\b')
    match_engine.add_matcher('zcommit',     r'\bzcommit[-\s:]*#([0-9]{1,5})\b')
    match_engine.add_matcher('RHBZ',        r'\bRHBZ[-\s:]#([0-9]{4,7})\b')
    match_engine.add_matcher('pag-screen',  r'\bpag-screen[-\s:]*#([0-9]{1,5})\b')
    match_engine.add_matcher('Mosh',        r'\bmosh[-\s:]*#([0-9]{1,5})\b')
    match_engine.add_matcher('Zulip',       r'\bzulip[-\s:]*#([0-9]{1,5})\b')
    match_engine.add_matcher('Scripts FAQ', r'\bscripts\sfaq[-\s:]*#([0-9]{1,5})\b')
    match_engine.add_matcher('Scripts FAQ', r'\bfaq[-\s:]*#([0-9]{1,5})\b', classes=['scripts'])
    match_engine.add_matcher('ESP',         r'#([0-9]{2,5})\b(?!-Ubuntu)', classes=['esp'])
    match_engine.add_matcher('ESP',         r'\besp[-\s:]*#([0-9]{1,5})\b')
    match_engine.add_matcher('Pokedex',     r'\bpokemon[-\s:]*#([0-9]{1,3})\b')
    match_engine.add_matcher('Pokedex',     r'#([0-9]{1,3})\b', classes=['lizdenys'])
    match_engine.add_matcher('MIT Class',   r'class\s([0-9a-z]{1,3}[.][0-9a-z]{1,4})\b')
    match_engine.add_matcher('MIT Class',   r"what's\s([0-9a-z]{1,3}[.][0-9a-z]{1,4})\?\b")
    match_engine.add_matcher('MIT Class',   r'([0-9a-z]{1,3}[.][0-9]{1,4})\b', cond=lambda m: m.is_personal())
    match_engine.add_matcher('whats',       r'whats ([0-9a-z,:;-]{2,10})\b')
    match_engine.add_matcher('Bible',       r'Bible\(([\w :-]+)\)')
    match_engine.add_matcher('XKCD',        r'\bxkcd[-\s:]#([0-9]{1,5})\b')
    match_engine.add_matcher('Unicode',     r'\bu\+([0-9a-fA-F]{2,6})\b')
    match_engine.add_matcher('Unicode Character',   r'\bunicode\((.)\)')
    match_engine.add_matcher('Airport',     r'\b([0-9A-Z]{3,4}(?:[.](?:IATA|FAA))?)\s[Aa]irport\b', flags=0)
    match_engine.add_matcher('Assassin',    r'\b(combo)\b', classes=['assassin'])
    match_engine.add_matcher('Assassin',    r'\b(combination)\b', classes=['assassin'])
    match_engine.add_matcher('SCIENCE',     r'^(science)$', classes=['axs'])
    match_engine.add_matcher('Debothena Test', r'\bdebothena test[-\s:]*#([0-9]{1,5})\b')
    match_engine.add_matcher('Puzzle Editing', r'\bpuzzle[ -]editing[-\s:]*#([0-9]{1,5})\b')

    match_engine.add_trac('Django', 'https://code.djangoproject.com', classes=[])
    match_engine.add_trac('Debathena', 'http://debathena.mit.edu/trac', classes=['debathena', 'jdreed', ])
    match_engine.add_trac('Linerva', 'http://debathena.mit.edu/trac', classes=['linerva', ])
    match_engine.add_trac('Scripts', 'http://scripts.mit.edu/trac', )
    match_engine.add_trac('XVM', 'http://xvm.scripts.mit.edu/trac', )
    match_engine.add_trac('Barnowl', 'http://barnowl.mit.edu', )
    match_engine.add_trac('Zephyr', 'http://zephyr.1ts.org', classes=['zephyr-dev'])
    match_engine.add_trac('SIPB', 'http://sipb.mit.edu/trac', )
    match_engine.add_trac('Remit', 'http://remit.scripts.mit.edu/trac', )
    match_engine.add_trac('etherpad.mit.edu', 'http://etherpad.scripts.mit.edu/trac', )
    match_engine.add_trac('ASA', 'http://asa.mit.edu/trac', )

def parse_args():
    usage = ('usage: %prog'
        + ' [--no-personals]'
        + ' [--protocol=zephyr|zulip]'
        + ' [--zulip-rc]'
        + ' [--default-classes]'
        + ' [--class=class ...]'
    )
    parser = OptionParser(usage=usage)
    parser.add_option('--no-personals', dest='no_personals',
        default=False, action='store_true',
        help='Disable replying to personals',
    )
    parser.add_option('-p', '--protocol', dest='protocol', default='zephyr', )
    parser.add_option('--zulip-rc', dest='zuliprc', default=None)
    parser.add_option('--default-classes', dest='default_classes',
            default=False, action='store_true',
            help='Sub to a default set of classes',
    )
    parser.add_option('-c', '--class', dest='classes',
            default=[], action='append',
            help='Sub to additional classes',
    )
    (options, args) = parser.parse_args()
    if len(args) != 0:
        parser.error("got %d arguments; expected none" % (len(args), ))
    if options.protocol not in ('zephyr', 'zulip'):
        parser.error("the only supported protocols are zephyr and zulip; you requested %s" % (options.protocol, ))
    if options.zuliprc and options.protocol != 'zulip':
        parser.error('Protocol must be "zulip" if --zulip-rc is provided.')
    if options.protocol != 'zephyr':
        if options.default_classes or options.classes:
            parser.error('Protocol must be "zephyr" if --default-classes or --class is provided.')
    return options, args

def run_with_args(match_engine):
    options, args = parse_args()

    match_engine.ignore_personals = options.no_personals
    if options.default_classes:
        add_default_classes(match_engine)
    if options.classes:
        match_engine.add_classes(options.classes)

    if options.protocol == 'zephyr':
        import chiron_zephyr as chiron_protocol
    elif options.protocol == 'zulip':
        import chiron_zulip as chiron_protocol
    else:
        raise ValueError
    chiron_protocol.main(match_engine, options)

def main():
    match_engine = init_match_engine()
    run_with_args(match_engine)

if __name__ == '__main__':
    main()
