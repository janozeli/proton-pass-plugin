"""Core-dump regressions; actual crashes run only with a file-based core pattern."""
import json, os, resource, subprocess, sys, unittest
from unittest.mock import mock_open, patch
from harness import Operator, error, install, server_env, start, write, SERVER

sys.path.insert(0, os.path.dirname(SERVER))
import proton_pass_mcp as server

ARGS = {"argv": ["/bin/true"], "env": {"PW": "pass://share1/item1/pin"}, "reason": "core regression"}
ERROR = "run refused: external core dump collector is not supported"


class CoreTests(unittest.TestCase):
    def test_external_collectors_are_refused_before_secret_access(self):
        for pattern in ("|/usr/lib/systemd/systemd-coredump %P %c %e\n", "|/collector\n", "@/collector.sock\n"):
            with self.subTest(pattern=pattern), patch.object(server, "open", mock_open(read_data=pattern), create=True), \
                    patch.object(server, "view_item", return_value={"content": {"title": "test"}}) as view, \
                    patch.object(server, "release", return_value="allow") as release, \
                    patch.object(server.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(server.PassError, ERROR):
                    server.run_approved(ARGS)
                view.assert_not_called()
                release.assert_not_called()
                launch.assert_not_called()

    def test_unreadable_core_policy_fails_closed(self):
        with patch.object(server, "open", side_effect=OSError("unreadable"), create=True), \
                patch.object(server, "view_item", return_value={"content": {"title": "test"}}) as view, \
                patch.object(server, "release", return_value="allow"), patch.object(server.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(server.PassError, "cannot verify core dump policy"):
                server.run_approved(ARGS)
            view.assert_not_called()
            launch.assert_not_called()

    def test_cli_and_exec_descendants_inherit_irreversible_zero_limits(self):
        # No crash here: simulate an accepted host policy without changing the host.
        d = install()
        write(d, "pass-cli", "#!" + sys.executable + "\nimport os,resource,sys\n"
              "assert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)\n"
              "try: resource.setrlimit(resource.RLIMIT_CORE,(1,1))\n"
              "except (ValueError,OSError): pass\n"
              "else: sys.exit(42)\n"
              "os.execv('/usr/bin/python3',['/usr/bin/python3','-c',"
              "'import resource; assert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)'])\n")
        with patch.object(server, "open", mock_open(read_data="core\n"), create=True), \
                patch.object(server, "view_item", return_value={"content": {"title": "test"}}), \
                patch.object(server, "release", return_value="allow"), \
                patch.object(server, "PASS_CLI", os.path.join(d, "pass-cli")), \
                patch.object(server, "SESSION", d):
            self.assertEqual(server.run_approved(ARGS), {"exit_code": 0})

    def test_live_policy_refuses_collectors_or_prevents_crash_artifacts(self):
        with open('/proc/sys/kernel/core_pattern') as f:
            external = f.read().startswith(('|', '@'))
        d, client = start()
        operator = Operator(d)
        try:
            if external:
                self.assertEqual(error(client, "run_approved", **ARGS), ERROR)
                self.assertFalse(operator.prompts)
                self.assertFalse(os.path.exists(os.path.join(d, 'calls')))
            else:
                # The parent survives the child's SIGABRT to inspect its private /tmp.
                # No real credentials are used, and there is no external collector.
                code = """import os,resource,signal,sys
assert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)
assert os.environ['PW']=='9876'
pid=os.fork()
if pid==0:
 os.abort()
_,status=os.waitpid(pid,0)
assert os.WTERMSIG(status)==signal.SIGABRT
assert not os.WCOREDUMP(status)
assert os.listdir('/tmp')==[]
"""
                for mode in ('allow', 'allow-net'):
                    operator.reply = {'op': mode}
                    self.assertEqual(client.call('run_approved', **{**ARGS, 'argv': ['/usr/bin/python3', '-c', code]}),
                                     {'exit_code': 0})
        finally:
            operator.close()
            client.close()


if __name__ == '__main__':
    unittest.main()
