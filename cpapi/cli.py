#   Copyright 2019 Check Point Software Technologies LTD

import argparse
import collections
import json
import os
import re
import sys
import traceback

from cpapi.utils import compatible_loads
from . import APIClient, APIClientArgs

if sys.version_info < (3,):
    string_type = basestring
else:
    string_type = str


def log(msg):
    msg = '%s' % msg
    sys.stderr.write(msg)
    sys.stderr.flush()

log.debug = os.environ.get('MGMT_CLI_DEBUG') == 'on'


def debug(*args, **kwargs):
    if log.debug:
        log(*args, **kwargs)


class Pairs(object):
    NO_KEY = None

    def __init__(self, pair_list=None):
        if pair_list is None:
            pair_list = []
        self.list = list(pair_list)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, repr(self.list))

    def __len__(self):
        return len(self.list)

    def __getitem__(self, i):
        return self.list[i]

    def __iter__(self):
        return ((k, v) for k, v in self.list)

    def prefixes(self):
        prefixes = collections.OrderedDict()
        for k, _ in self:
            prefix = k.partition('.')[0]
            prefixes[prefix] = None
        return prefixes.keys()

    def get(self, prefix):
        found = Pairs()
        suffixes = collections.OrderedDict()
        for k, v in self:
            if k == prefix:
                suffix = self.NO_KEY
            elif k.startswith(prefix + '.'):
                suffix = k[len(prefix) + 1:]
                if not suffix:
                    raise ValueError('empty suffix: "%s"' % k)
            else:
                continue
            if suffix in suffixes:
                raise ValueError('duplicate key: "%s"' % k)
            suffixes[suffix] = None
            found.add(suffix, v)
        if self.NO_KEY in suffixes and len(suffixes) != 1:
            suffixes.pop(self.NO_KEY)
            raise ValueError('mixed keys: ["%s" "%s"]' % (
                prefix, '" "'.join(['%s.%s' % (prefix, s) for s in suffixes])))
        return found

    def add(self, key, val):
        self.list.append((key, val))

    def to_obj(self):
        if len(self) == 1 and self[0][0] is Pairs.NO_KEY:
            val = self[0][1]
            if val in {'null', 'true', 'false'} or val[0] in '"{[':
                return compatible_loads(val)
            elif re.match(r'\d+$', val):
                return int(val, 10)
            return val
        pairs = Pairs()
        all_nums = True
        any_nums = False
        for prefix in self.prefixes():
            vals = self.get(prefix)
            if re.match(r'\d+$', prefix):
                prefix = int(prefix, 10)
                any_nums = True
            else:
                all_nums = False
            pairs.add(prefix, vals.to_obj())
        if not all_nums:
            if any_nums:
                raise ValueError('mixed (sub)keys: ["%s"]' % '" "'.join(
                    str(i[0]) for i in pairs))
            return collections.OrderedDict(pairs)
        return [i[1] for i in sorted(pairs)]


def safe_string(v):
    if isinstance(v, string_type) and re.match(
            r'[A-Za-z_][-0-9A-Za-z_]*$', v) and v.lower() not in {
                'null', 'true', 'yes', 'on', 'false', 'no', 'off',
                'infinity', 'nan', '---', '...'} and not re.match(
                    r'[0-9][0-9][0-9][0-9]-', v):
        return v
    return json.dumps(v)


def simple_yaml(root, as_string=True):
    """Print the configuration in a user friendly format."""

    if as_string:
        return '\n'.join(simple_yaml(root, False) + [''])
        return

    if not isinstance(root, (dict, list)) or not root:
        return [safe_string(root)]

    if isinstance(root, dict):
        items = root.items()
    else:
        items = ((None, v) for v in root)
    lines = []
    for k, v in items:
        v_lines = simple_yaml(v, False)
        indent = '  '
        if k is None:
            lines.append('- ' + v_lines.pop(0))
        else:
            lines.append(safe_string(k) + ':')
            if isinstance(v, list):
                indent = ''
            if not v or not isinstance(v, (dict, list)):
                lines[-1] += ' ' + v_lines.pop(0)
        lines.extend([indent + line for line in v_lines])
    return lines


class Format(argparse.Action):
    FORMATS = {
        'json': lambda o: json.dumps(o, indent=2),
        'text': simple_yaml}

    def __init__(self, option_strings, dest, default=None, **kwargs):
        if default:
            default = self.FORMATS[default]
        super(Format, self).__init__(
            option_strings, dest, default=default, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if values[0] not in self.FORMATS:
            raise ValueError('unknown format: "%s"' % values[0])
        setattr(namespace, self.dest, self.FORMATS[values[0]])


class Args(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) % 2:
            raise ValueError('odd number of arguments')
        if not len(values):
            val = {}
        elif len(values) == 2 and values[0] == '.':
            val = Pairs([(Pairs.NO_KEY, values[1])]).to_obj()
        else:
            val = Pairs(zip(values[::2], values[1::2])).to_obj()
        setattr(namespace, self.dest, val)


def pack(name):
    import pkgutil
    import zipfile
    base_file = os.path.basename(os.path.basename(__file__)).partition('.')[0]
    base_dir = os.path.basename(os.path.dirname(__file__))
    with open(name, 'wb') as f:
        f.write(b'#!/usr/bin/env python\n')
        with zipfile.ZipFile(f, 'a', zipfile.ZIP_DEFLATED) as zf:
            for f in ('__init__.py', 'api_exceptions.py', 'api_response.py',
                      'mgmt_api.py', base_file + '.py'):
                contents = pkgutil.get_data(base_dir, f)
                zf.writestr(os.path.join(base_dir, f), contents)
            zf.writestr('__main__.py', (
                'from %s.%s import run\nrun()\n' % (
                    base_dir, base_file)).encode('utf-8'))
    umask = os.umask(0o777)
    os.umask(umask)
    os.chmod(name, 0o755 & (0o7777 - umask))


def preprocess_argv(argv):
    # handle the 'pack' "command"
    # replace '... set host ...' with '... set-host ...'
    # for add/delete/show/set
    prog = [argv[0]]
    argv = argv[1:]
    command_index = -1
    for i, _ in enumerate(argv):
        if argv[i] in {'add', 'delete', 'show', 'set', 'pack'}:
            command_index = i
            break
    if command_index < 0:
        return prog + argv
    if command_index + 1 >= len(argv) or argv[command_index + 1][0] == '-':
        raise ValueError('cannot have a bare: "%s"' % argv[command_index])
    if argv[command_index] == 'pack':
        return pack(argv[command_index + 1])
    return (prog + argv[:command_index] +
            [argv[command_index] + '-' + argv[command_index + 1]] +
            argv[command_index + 2:])


def main(argv):
    NO_DEFAULT = object()
    parser = argparse.ArgumentParser(prog=argv[0])
    parser.add_argument(
        '--format', '-f', metavar='{json|text}', nargs=1, default='text',
        action=Format)
    args_def = [
        ('--debug', None, '{on|off}', 'MGMT_CLI_DEBUG'),
        ('--domain', '-d', 'DOMAIN', 'MGMT_CLI_DOMAIN'),
        ('--fingerprint', None, 'FINGERPRINT', 'MGMT_CLI_FINGERPRINT'),
        ('--management', '-m', 'SERVER', 'MGMT_CLI_MANAGEMENT'),
        ('--password', '-p', 'PASSWORD', 'MGMT_CLI_PASSWORD'),
        ('--port', None, 'PORT', 'MGMT_CLI_PORT'),
        ('--proxy', '-x', 'PROXY', 'MGMT_CLI_PROXY'),
        ('--root', '-r', '{true|false}', None),
        ('--session-id', None, 'SESSION-ID', 'MGMT_CLI_SESSION_ID'),
        ('--sync', None, '{true|false}', 'MGMT_CLI_SYNC'),
        ('--user', '-u', 'USER', 'MGMT_CLI_USER'),
        ('--version', '-v', 'VERSION', 'MGMT_CLI_VERSION'),
    ]
    for lname, sname, meta, env in args_def:
        pargs = [lname]
        if sname:
            pargs.append(sname)
        kwargs = {'metavar': meta}
        if env:
            kwargs['default'] = os.environ.get(env, NO_DEFAULT)
        else:
            kwargs['default'] = NO_DEFAULT
        parser.add_argument(*pargs, **kwargs)
    parser.add_argument('command', metavar='COMMAND')
    parser.add_argument('arg', metavar='ARG', nargs='*', action=Args)
    argv = preprocess_argv(argv)
    if argv is None:
        return
    args = parser.parse_args(args=argv[1:])
    for lname, _, _, _ in args_def:
        attr = lname[2:].replace('-', '_')
        if getattr(args, attr, None) is NO_DEFAULT:
            delattr(args, attr)
    client_args = {}
    if getattr(args, 'debug', 'off') == 'on':
        log.debug = True
        client_args['debug_file'] = sys.stderr  # dummy
        # FIXME: remove when save_debug_data is fixed
        APIClient.save_debug_data = lambda self: sys.stderr.write(
            'API calls: %s\n' % json.dumps(self.api_calls, indent=2))
        client_args['http_debug_level'] = 1
    debug('args: %s\n' % args)
    if hasattr(args, 'port'):
        args.port = int(args.port)
    if hasattr(args, 'proxy'):
        args.proxy_host, _, port = args.proxy.partition(':')
        if '@' in args.proxy_host:
            raise Exception('proxy authentication is not implemented')
        if port:
            args.proxy_port = int(port)
    clargs_def = [
        ('management', 'server'),
        ('port', None),
        ('fingerprint', None),
        ('proxy_host', None),
        ('proxy_port', None),
    ]
    for name, cla in clargs_def:
        val = getattr(args, name, None)
        if cla is None:
            cla = name
        if val is not None:
            client_args[cla] = val
    debug('client args: %s\n' % client_args)
    args.domain = getattr(args, 'domain', None)
    args.root = compatible_loads(getattr(args, 'root', 'false'))
    args.sync = compatible_loads(getattr(args, 'sync', 'true'))
    with APIClient(APIClientArgs(**client_args)) as client:
        call_args = {}
        if hasattr(args, 'session_id'):
            call_args['sid'] = args.session_id
        elif args.root:
            client.login_as_root(domain=args.domain)
        elif hasattr(args, 'password') and args.command != 'login':
            client.login(username=args.user, password=args.password,
                         domain=args.domain)
        if hasattr(args, 'version'):
            # FIXME: remove when api_call accepts api_version
            client.api_version = args.version
        saved_stdout = sys.stdout
        publish_response = None
        try:
            sys.stdout = sys.stderr
            if args.command == 'login':
                for attr in ('user', 'password', 'domain'):
                    if attr not in args.arg:
                        val = getattr(args, attr, None)
                        if val:
                            args.arg[attr] = val
            response = client.api_call(
                args.command, args.arg, wait_for_task=args.sync,
                **call_args).as_dict()
            if any(args.command.startswith(p) for p in {
                    'set-', 'add-', 'delete-', 'get-interfaces'}):
                publish_response = client.api_call(
                    'publish', {}, wait_for_task=args.sync).as_dict()
        finally:
            sys.stdout = saved_stdout
    if not response.get('success'):
        raise Exception(json.dumps(response, indent=2))
    if publish_response and not publish_response.get('success'):
        raise Exception(json.dumps(publish_response, indent=2))
    sys.stdout.write(args.format(response.get('data')))


def run():
    try:
        main(sys.argv)
    except SystemExit as e:
        sys.exit(e.code)
    except:
        t, v, tb = sys.exc_info()
        debug('Traceback (most recent call last):\n%s' % ''.join(
            traceback.format_tb(tb)))
        log('%s' % ''.join(traceback.format_exception_only(t, v)))
        sys.exit(1)

if __name__ == '__main__':
    run()
