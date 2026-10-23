import os
import sys
import threading
import unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))
from mcp_peer import Peer, ConsentError


class PeerTests(unittest.TestCase):
    def request(self, cap, responder, network=False):
        messages = []
        def send(msg):
            messages.append(msg)
            responder(peer, msg)
        peer = Peer(send)
        peer.capabilities = cap
        return peer.consent('Approve this exact operation', network), messages

    def test_unmatched_reply_cannot_approve(self):
        def reply(peer, msg):
            peer.receive({'jsonrpc': '2.0', 'id': 'wrong', 'result': {'action': 'accept', 'content': {'approve': True}}})
            self.assertFalse(peer.pending[msg['id']][0].is_set())
            peer.receive({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'action': 'decline'}})
        with self.assertRaisesRegex(ConsentError, 'denied'):
            self.request({'elicitation': {}}, reply)

    def test_network_requires_an_explicit_boolean(self):
        def reply(peer, msg):
            peer.receive({'id': msg['id'], 'result': {'action': 'accept', 'content': {'approve': True, 'allow_network': 'true'}}})
        result, messages = self.request({'elicitation': {'form': {}}}, reply, True)
        self.assertEqual(result, 'allow')
        self.assertEqual(messages[0]['params']['requestedSchema']['properties']['allow_network']['default'], False)

    def test_url_only_capability_does_not_enable_forms(self):
        with self.assertRaisesRegex(ConsentError, 'unavailable'):
            self.request({'elicitation': {'url': {}}}, lambda *_: self.fail('must not request'))

    def test_disconnect_unblocks_and_denies(self):
        with self.assertRaisesRegex(ConsentError, 'denied'):
            self.request({'elicitation': {}}, lambda peer, msg: peer.close())

    def test_malformed_accept_is_not_consent(self):
        for response in (None, [], {'action': 'accept', 'content': []}, {'action': 'accept', 'content': {'approve': 'true'}}):
            def reply(peer, msg):
                peer.receive({'id': msg['id'], 'result': response})
            with self.assertRaises(ConsentError):
                self.request({'elicitation': {}}, reply)


if __name__ == '__main__':
    unittest.main()
