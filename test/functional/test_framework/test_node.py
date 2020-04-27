#!/usr/bin/env python3
# Copyright (c) 2017-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class for sind node under test"""

import contextlib
import decimal
import errno
from enum import Enum
import http.client
import json
import logging
import os
import re
import subprocess
import tempfile
import time
import urllib.parse

from .authproxy import JSONRPCException
from .descriptors import descsum_create
from .util import (
    append_config,
    delete_cookie_file,
    get_rpc_proxy,
    rpc_url,
    wait_until,
    p2p_port,
)

# For Python 3.4 compatibility
JSONDecodeError = getattr(json, "JSONDecodeError", ValueError)

SIND_PROC_WAIT_TIMEOUT = 60


class FailedToStartError(Exception):
    """Raised when a node fails to start correctly."""


class ErrorMatch(Enum):
    FULL_TEXT = 1
    FULL_REGEX = 2
    PARTIAL_REGEX = 3


class TestNode():
    """A class for representing a sind node under test.

    This class contains:

    - state about the node (whether it's running, etc)
    - a Python subprocess.Popen object representing the running process
    - an RPC connection to the node
    - one or more P2P connections to the node


    To make things easier for the test writer, any unrecognised messages will
    be dispatched to the RPC connection."""

    def __init__(self, i, datadir, *, chain, rpchost, timewait, bitcoind, bitcoin_cli, coverage_dir, cwd, extra_conf=None, extra_args=None, use_cli=False, start_perf=False, use_valgrind=False, version=None, descriptors=False):
        """
        Kwargs:
            start_perf (bool): If True, begin profiling the node with `perf` as soon as
                the node starts.
        """

        self.index = i
        self.datadir = datadir
        self.stdout_dir = os.path.join(self.datadir, "stdout")
        self.stderr_dir = os.path.join(self.datadir, "stderr")
        self.rpchost = rpchost
        self.rpc_timeout = timewait
        self.binary = sind
        self.coverage_dir = coverage_dir
        self.cwd = cwd
        self.descriptors = descriptors
        if extra_conf is not None:
            append_config(datadir, extra_conf)
        # Most callers will just need to add extra args to the standard list below.
        # For those callers that need more flexibility, they can just set the args property directly.
        # Note that common args are set in the config file (see initialize_datadir)
        self.extra_args = extra_args
        self.args = [
            self.binary,
            "-datadir=" + self.datadir,
            "-logtimemicros",
            "-debug",
            "-debugexclude=libevent",
            "-debugexclude=leveldb",
            "-mocktime=" + str(mocktime),
            "-uacomment=testnode%d" % i
        ]

        self.cli = TestNodeCLI(sin_cli, self.datadir)
        self.use_cli = use_cli

        self.running = False
        self.process = None
        self.rpc_connected = False
        self.rpc = None
        self.url = None
        self.log = logging.getLogger('TestFramework.node%d' % i)
        self.cleanup_on_exit = True # Whether to kill the node when this object goes away

        self.p2ps = []

    def get_deterministic_priv_key(self):
        """Return a deterministic priv key in base58, that only depends on the node's index"""
        PRIV_KEYS = [
            # adress , privkey
            ('mjTkW3DjgyZck4KbiRusZsqTgaYTxdSz6z', 'cVpF924EspNh8KjYsfhgY96mmxvT6DgdWiTYMtMjuM74hJaU5psW'),
            ('msX6jQXvxiNhx3Q62PKeLPrhrqZQdSimTg', 'cUxsWyKyZ9MAQTaAhUQWJmBbSvHMwSmuv59KgxQV7oZQU3PXN3KE'),
            ('mnonCMyH9TmAsSj3M59DsbH8H63U3RKoFP', 'cTrh7dkEAeJd6b3MRX9bZK8eRmNqVCMH3LSUkE3dSFDyzjU38QxK'),
            ('mqJupas8Dt2uestQDvV2NH3RU8uZh2dqQR', 'cVuKKa7gbehEQvVq717hYcbE9Dqmq7KEBKqWgWrYBa2CKKrhtRim'),
            ('msYac7Rvd5ywm6pEmkjyxhbCDKqWsVeYws', 'cQDCBuKcjanpXDpCqacNSjYfxeQj8G6CAtH1Dsk3cXyqLNC4RPuh'),
            ('n2rnuUnwLgXqf9kk2kjvVm8R5BZK1yxQBi', 'cQakmfPSLSqKHyMFGwAqKHgWUiofJCagVGhiB4KCainaeCSxeyYq'),
            ('myzuPxRwsf3vvGzEuzPfK9Nf2RfwauwYe6', 'cQMpDLJwA8DBe9NcQbdoSb1BhmFxVjWD5gRyrLZCtpuF9Zi3a9RK'),
            ('mumwTaMtbxEPUswmLBBN3vM9oGRtGBrys8', 'cSXmRKXVcoouhNNVpcNKFfxsTsToY5pvB9DVsFksF1ENunTzRKsy'),
            ('mpV7aGShMkJCZgbW7F6iZgrvuPHjZjH9qg', 'cSoXt6tm3pqy43UMabY6eUTmR3eSUYFtB2iNQDGgb3VUnRsQys2k'),
        ]
        return PRIV_KEYS[self.index]

    def _node_msg(self, msg: str) -> str:
        """Return a modified msg that identifies this node by its index as a debugging aid."""
        return "[node %d] %s" % (self.index, msg)

    def _raise_assertion_error(self, msg: str):
        """Raise an AssertionError with msg modified to identify this node."""
        raise AssertionError(self._node_msg(msg))

    def __del__(self):
        # Ensure that we don't leave any sind processes lying around after
        # the test ends
        if self.process and self.cleanup_on_exit:
            # Should only happen on test failure
            # Avoid using logger, as that may have already been shutdown when
            # this destructor is called.
            print(self._node_msg("Cleaning up leftover process"))
            self.process.kill()

    def __getattr__(self, name):
        """Dispatches any unrecognised messages to the RPC connection or a CLI instance."""
        if self.use_cli:
            return getattr(RPCOverloadWrapper(self.cli, True, self.descriptors), name)
        else:
            assert self.rpc_connected and self.rpc is not None, self._node_msg("Error: no RPC connection")
            return getattr(RPCOverloadWrapper(self.rpc, descriptors=self.descriptors), name)

    def start(self, extra_args=None, *, stdout=None, stderr=None, **kwargs):
        """Start the node."""
        if extra_args is None:
            extra_args = self.extra_args

        # Add a new stdout and stderr file each time sind is started
        if stderr is None:
            stderr = tempfile.NamedTemporaryFile(dir=self.stderr_dir, delete=False)
        if stdout is None:
            stdout = tempfile.NamedTemporaryFile(dir=self.stdout_dir, delete=False)
        self.stderr = stderr
        self.stdout = stdout

        # Delete any existing cookie file -- if such a file exists (eg due to
        # unclean shutdown), it will get overwritten anyway by sind, and
        # potentially interfere with our attempt to authenticate
        delete_cookie_file(self.datadir)

        # add environment variable LIBC_FATAL_STDERR_=1 so that libc errors are written to stderr and not the terminal
        subp_env = dict(os.environ, LIBC_FATAL_STDERR_="1")

        self.process = subprocess.Popen(self.args + extra_args, env=subp_env, stdout=stdout, stderr=stderr, **kwargs)

        self.running = True
        self.log.debug("sind started, waiting for RPC to come up")

    def wait_for_rpc_connection(self):
        """Sets up an RPC connection to the sind process. Returns False if unable to connect."""
        # Poll at a rate of four times per second
        poll_per_s = 4
        for _ in range(poll_per_s * self.rpc_timeout):
            if self.process.poll() is not None:
                raise FailedToStartError(self._node_msg(
                    'sind exited with status {} during initialization'.format(self.process.returncode)))
            try:
                self.rpc = get_rpc_proxy(rpc_url(self.datadir, self.index, self.rpchost), self.index, timeout=self.rpc_timeout, coveragedir=self.coverage_dir)
                self.rpc.getblockcount()
                # If the call to getblockcount() succeeds then the RPC connection is up
                self.rpc_connected = True
                self.url = self.rpc.url
                self.log.debug("RPC successfully started")
                return
            except IOError as e:
                if e.errno != errno.ECONNREFUSED:  # Port not yet open?
                    raise  # unknown IO error
            except JSONRPCException as e:  # Initialization phase
                if e.error['code'] != -28:  # RPC in warmup?
                    raise  # unknown JSON RPC exception
            except ValueError as e:  # cookie file not found and no rpcuser or rpcassword. sind still starting
                if "No RPC credentials" not in str(e):
                    raise
            time.sleep(1.0 / poll_per_s)
        self._raise_assertion_error("Unable to connect to sind")

    def get_wallet_rpc(self, wallet_name):
        if self.use_cli:
            return RPCOverloadWrapper(self.cli("-rpcwallet={}".format(wallet_name)), True, self.descriptors)
        else:
            assert self.rpc_connected and self.rpc, self._node_msg("RPC not connected")
            wallet_path = "wallet/{}".format(urllib.parse.quote(wallet_name))
            return RPCOverloadWrapper(self.rpc / wallet_path, descriptors=self.descriptors)

    def stop_node(self, expected_stderr='', wait=0):
        """Stop the node."""
        if not self.running:
            return
        self.log.debug("Stopping node")
        try:
            self.stop(wait=wait)
        except http.client.CannotSendRequest:
            self.log.exception("Unable to stop node.")

        # Check that stderr is as expected
        self.stderr.seek(0)
        stderr = self.stderr.read().decode('utf-8').strip()
        if stderr != expected_stderr:
            raise AssertionError("Unexpected stderr {} != {}".format(stderr, expected_stderr))

        self.stdout.close()
        self.stderr.close()

        del self.p2ps[:]

    def is_node_stopped(self):
        """Checks whether the node has stopped.

        Returns True if the node has stopped. False otherwise.
        This method is responsible for freeing resources (self.process)."""
        if not self.running:
            return True
        return_code = self.process.poll()
        if return_code is None:
            return False

        # process has stopped. Assert that it didn't return an error code.
        assert return_code == 0, self._node_msg(
            "Node returned non-zero exit code (%d) when stopping" % return_code)
        self.running = False
        self.process = None
        self.rpc_connected = False
        self.rpc = None
        self.log.debug("Node stopped")
        return True

    def wait_until_stopped(self, timeout=SIND_PROC_WAIT_TIMEOUT):
        wait_until(self.is_node_stopped, timeout=timeout)

    @contextlib.contextmanager
    def assert_debug_log(self, expected_msgs):
        debug_log = os.path.join(self.datadir, 'regtest', 'debug.log')
        with open(debug_log, encoding='utf-8') as dl:
            dl.seek(0, 2)
            prev_size = dl.tell()
        try:
            yield
        finally:
            with open(debug_log, encoding='utf-8') as dl:
                dl.seek(prev_size)
                log = dl.read()
            print_log = " - " + "\n - ".join(log.splitlines())
            for expected_msg in expected_msgs:
                if re.search(re.escape(expected_msg), log, flags=re.MULTILINE) is None:
                    self._raise_assertion_error('Expected message "{}" does not partially match log:\n\n{}\n\n'.format(expected_msg, print_log))

    def assert_start_raises_init_error(self, extra_args=None, expected_msg=None, match=ErrorMatch.FULL_TEXT, *args, **kwargs):
        """Attempt to start the node and expect it to raise an error.

        extra_args: extra arguments to pass through to sind
        expected_msg: regex that stderr should match when sind fails

        Will throw if sind starts without an error.
        Will throw if an expected_msg is provided and it does not match sind's stdout."""
        with tempfile.NamedTemporaryFile(dir=self.stderr_dir, delete=False) as log_stderr, \
             tempfile.NamedTemporaryFile(dir=self.stdout_dir, delete=False) as log_stdout:
            try:
                self.start(extra_args, stdout=log_stdout, stderr=log_stderr, *args, **kwargs)
                self.wait_for_rpc_connection()
                self.stop_node()
                self.wait_until_stopped()
            except FailedToStartError as e:
                self.log.debug('sind failed to start: %s', e)
                self.running = False
                self.process = None
                # Check stderr for expected message
                if expected_msg is not None:
                    log_stderr.seek(0)
                    stderr = log_stderr.read().decode('utf-8').strip()
                    if match == ErrorMatch.PARTIAL_REGEX:
                        if re.search(expected_msg, stderr, flags=re.MULTILINE) is None:
                            self._raise_assertion_error(
                                'Expected message "{}" does not partially match stderr:\n"{}"'.format(expected_msg, stderr))
                    elif match == ErrorMatch.FULL_REGEX:
                        if re.fullmatch(expected_msg, stderr) is None:
                            self._raise_assertion_error(
                                'Expected message "{}" does not fully match stderr:\n"{}"'.format(expected_msg, stderr))
                    elif match == ErrorMatch.FULL_TEXT:
                        if expected_msg != stderr:
                            self._raise_assertion_error(
                                'Expected message "{}" does not fully match stderr:\n"{}"'.format(expected_msg, stderr))
            else:
                if expected_msg is None:
                    assert_msg = "sind should have exited with an error"
                else:
                    assert_msg = "sind should have exited with expected error " + expected_msg
                self._raise_assertion_error(assert_msg)

    def node_encrypt_wallet(self, passphrase):
        """"Encrypts the wallet.

        This causes sind to shutdown, so this method takes
        care of cleaning up resources."""
        self.encryptwallet(passphrase)
        self.wait_until_stopped()

    def add_p2p_connection(self, p2p_conn, *, wait_for_verack=True, **kwargs):
        """Add a p2p connection to the node.

        This method adds the p2p connection to the self.p2ps list and also
        returns the connection to the caller."""
        if 'dstport' not in kwargs:
            kwargs['dstport'] = p2p_port(self.index)
        if 'dstaddr' not in kwargs:
            kwargs['dstaddr'] = '127.0.0.1'

        p2p_conn.peer_connect(**kwargs)()
        self.p2ps.append(p2p_conn)
        if wait_for_verack:
            p2p_conn.wait_for_verack()

        return p2p_conn

    @property
    def p2p(self):
        """Return the first p2p connection

        Convenience property - most tests only use a single p2p connection to each
        node, so this saves having to write node.p2ps[0] many times."""
        assert self.p2ps, self._node_msg("No p2p connection")
        return self.p2ps[0]

    def disconnect_p2ps(self):
        """Close all p2p connections to the node."""
        for p in self.p2ps:
            p.peer_disconnect()
        del self.p2ps[:]

class TestNodeCLIAttr:
    def __init__(self, cli, command):
        self.cli = cli
        self.command = command

    def __call__(self, *args, **kwargs):
        return self.cli.send_cli(self.command, *args, **kwargs)

    def get_request(self, *args, **kwargs):
        return lambda: self(*args, **kwargs)

class TestNodeCLI():
    """Interface to sin-cli for an individual node"""

    def __init__(self, binary, datadir):
        self.options = []
        self.binary = binary
        self.datadir = datadir
        self.input = None
        self.log = logging.getLogger('TestFramework.sincli')

    def __call__(self, *options, input=None):
        # TestNodeCLI is callable with sin-cli command-line options
        cli = TestNodeCLI(self.binary, self.datadir)
        cli.options = [str(o) for o in options]
        cli.input = input
        return cli

    def __getattr__(self, command):
        return TestNodeCLIAttr(self, command)

    def batch(self, requests):
        results = []
        for request in requests:
            try:
                results.append(dict(result=request()))
            except JSONRPCException as e:
                results.append(dict(error=e))
        return results

    def send_cli(self, command=None, *args, **kwargs):
        """Run sin-cli command. Deserializes returned string as python object."""
        pos_args = [str(arg).lower() if type(arg) is bool else str(arg) for arg in args]
        named_args = [str(key) + "=" + str(value) for (key, value) in kwargs.items()]
        assert not (pos_args and named_args), "Cannot use positional arguments and named arguments in the same sin-cli call"
        p_args = [self.binary, "-datadir=" + self.datadir] + self.options
        if named_args:
            p_args += ["-named"]
        if command is not None:
            p_args += [command]
        p_args += pos_args + named_args
        self.log.debug("Running sin-cli command: %s" % command)
        process = subprocess.Popen(p_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        cli_stdout, cli_stderr = process.communicate(input=self.input)
        returncode = process.poll()
        if returncode:
            match = re.match(r'error code: ([-0-9]+)\nerror message:\n(.*)', cli_stderr)
            if match:
                code, message = match.groups()
                raise JSONRPCException(dict(code=int(code), message=message))
            # Ignore cli_stdout, raise with cli_stderr
            raise subprocess.CalledProcessError(returncode, self.binary, output=cli_stderr)
        try:
            return json.loads(cli_stdout, parse_float=decimal.Decimal)
        except JSONDecodeError:
            return cli_stdout.rstrip("\n")

class RPCOverloadWrapper():
    def __init__(self, rpc, cli=False, descriptors=False):
        self.rpc = rpc
        self.is_cli = cli
        self.descriptors = descriptors

    def __getattr__(self, name):
        return getattr(self.rpc, name)

    def createwallet(self, wallet_name, disable_private_keys=None, blank=None, passphrase=None, avoid_reuse=None, descriptors=None):
        if self.is_cli:
            if disable_private_keys is None:
                disable_private_keys = 'null'
            if blank is None:
                blank = 'null'
            if passphrase is None:
                passphrase = ''
            if avoid_reuse is None:
                avoid_reuse = 'null'
        if descriptors is None:
            descriptors = self.descriptors
        return self.__getattr__('createwallet')(wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors)

    def importprivkey(self, privkey, label=None, rescan=None):
        wallet_info = self.getwalletinfo()
        if self.is_cli:
            if label is None:
                label = 'null'
            if rescan is None:
                rescan = 'null'
        if 'descriptors' not in wallet_info or ('descriptors' in wallet_info and not wallet_info['descriptors']):
            return self.__getattr__('importprivkey')(privkey, label, rescan)
        desc = descsum_create('combo(' + privkey + ')')
        req = [{
            'desc': desc,
            'timestamp': 0 if rescan else 'now',
            'label': label if label else ''
        }]
        import_res = self.importdescriptors(req)
        if not import_res[0]['success']:
            raise JSONRPCException(import_res[0]['error'])

    def addmultisigaddress(self, nrequired, keys, label=None, address_type=None):
        wallet_info = self.getwalletinfo()
        if self.is_cli:
            if label is None:
                label = 'null'
            if address_type is None:
                address_type = 'null'
        if 'descriptors' not in wallet_info or ('descriptors' in wallet_info and not wallet_info['descriptors']):
            return self.__getattr__('addmultisigaddress')(nrequired, keys, label, address_type)
        cms = self.createmultisig(nrequired, keys, address_type)
        req = [{
            'desc': cms['descriptor'],
            'timestamp': 0,
            'label': label if label else ''
        }]
        import_res = self.importdescriptors(req)
        if not import_res[0]['success']:
            raise JSONRPCException(import_res[0]['error'])
        return cms

    def importpubkey(self, pubkey, label=None, rescan=None):
        wallet_info = self.getwalletinfo()
        if self.is_cli:
            if label is None:
                label = 'null'
            if rescan is None:
                rescan = 'null'
        if 'descriptors' not in wallet_info or ('descriptors' in wallet_info and not wallet_info['descriptors']):
            return self.__getattr__('importpubkey')(pubkey, label, rescan)
        desc = descsum_create('combo(' + pubkey + ')')
        req = [{
            'desc': desc,
            'timestamp': 0 if rescan else 'now',
            'label': label if label else ''
        }]
        import_res = self.importdescriptors(req)
        if not import_res[0]['success']:
            raise JSONRPCException(import_res[0]['error'])

    def importaddress(self, address, label=None, rescan=None, p2sh=None):
        wallet_info = self.getwalletinfo()
        if self.is_cli:
            if label is None:
                label = 'null'
            if rescan is None:
                rescan = 'null'
            if p2sh is None:
                p2sh = 'null'
        if 'descriptors' not in wallet_info or ('descriptors' in wallet_info and not wallet_info['descriptors']):
            return self.__getattr__('importaddress')(address, label, rescan, p2sh)
        is_hex = False
        try:
            int(address ,16)
            is_hex = True
            desc = descsum_create('raw(' + address + ')')
        except:
            desc = descsum_create('addr(' + address + ')')
        reqs = [{
            'desc': desc,
            'timestamp': 0 if rescan else 'now',
            'label': label if label else ''
        }]
        if is_hex and p2sh:
            reqs.append({
                'desc': descsum_create('p2sh(raw(' + address + '))'),
                'timestamp': 0 if rescan else 'now',
                'label': label if label else ''
            })
        import_res = self.importdescriptors(reqs)
        for res in import_res:
            if not res['success']:
                raise JSONRPCException(res['error'])
