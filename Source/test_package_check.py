"""Supply check: user data and secrets never pass `package_check.py`."""
import pathlib, tempfile, unittest, zipfile
import package_check as pc


class PackageCheck(unittest.TestCase):
    def phrase(self):
        words = sorted(pc.WORDS)
        return ' '.join(words[i * 7] for i in range(24))

    def test_secrets_and_user_data_are_found(self):
        self.assertIsNotNone(pc.WORDS, 'BIP39 word list (vendor) needed')
        bad = {
            'TESTNET_FUNDED_SEEDS.local.txt': 'x',
            'notes/wallet.txt': f'# my wallet\n{self.phrase()}\n',
            'run/send-context.json': '{"ctx":{"sec_' + 'key":"0a0b0c"}}',  # split: this file is shipped
            'user/wallet-outputs.jsonl': '{"meta":"grinsight-wallet"}',
            'user/pending-receives.jsonl': '{"kind":"rec' + 'eive","wallet":1,"slate_id":"x"}',
            'doc/keys.md': 'ADDRESS_SECRET_HEX=' + 'ab' * 32,
            'doc/pay.md': 'BEGINSLATEPACK. ' + ('4H1qx1wHe668tFW ' * 12) + 'ENDSLATEPACK.',
            'evidence/user-run-1/30-wallet.log': 'GAP=OK',
            'state/state.ust': 'bin',
        }
        with tempfile.TemporaryDirectory() as d:
            for rel, text in bad.items():
                p = pathlib.Path(d, rel)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            found = {}
            for rel, data in pc.iter_target(d):
                for f in pc.scan_bytes(rel, data):
                    found.setdefault(f[0], []).append(f[2])
            for rel in bad:
                self.assertIn(rel, found, f'{rel} not flagged')
            # the same inside a zip
            z = pathlib.Path(d, 'ship.zip')
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr('a/seed.txt', self.phrase())
            self.assertEqual(pc.cmd_scan(type('A', (), {'path': str(z)})()), 1)

    def test_clean_sources_pass(self):
        ok = {
            'src/lib.rs': 'fn main() { let w = vec!["abandon"; 23]; }  // test data in code\n',
            'README.md': 'Give the slatepack (BEGINSLATEPACK. ... ENDSLATEPACK.) to the receiver.\n'
                         'These are the funded testnet wallets for the experiment, keep them offline please\n',
            'grinsight-state/release-keys.txt': '1 abcdef\n',
            # the signed release checkpoint: top of the pack and in the GitHub tree
            'release/checkpoint.rwm': 'version 1\n',
            'Source/release/checkpoint.rwm': 'version 1\n',
        }
        with tempfile.TemporaryDirectory() as d:
            for rel, text in ok.items():
                p = pathlib.Path(d, rel)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            self.assertEqual(pc.cmd_scan(type('A', (), {'path': d})()), 0)

    def test_chain_state_outside_release_is_flagged(self):
        for rel in ('Source/evidence-x/checkpoint.rwm', 'Source/UI/state.rwm', 'Documents/release/x.rwm'):
            self.assertTrue(pc.scan_bytes(rel, b'version 1\n'), rel)

    def test_allow_list_has_no_user_data_dirs(self):
        for entry in pc.ALLOW + pc.VENDOR:
            first = entry.split('/')[0]
            self.assertNotIn(first, {'evidence', 'sessions', '.data', 'data', '.build'})

    def test_semver_requirements(self):
        m = pc.version_matches
        self.assertTrue(m('0.6.3', '>= 0.6.3'))
        self.assertFalse(m('0.6.2', '>= 0.6.3'))
        self.assertTrue(m('0.4.7', '^0.4.5'))
        self.assertFalse(m('0.5.0', '^0.4.5'))
        self.assertTrue(m('1.9.0', '^1.2'))
        self.assertFalse(m('2.0.0', '^1.2'))
        self.assertTrue(m('0.0.3', '^0.0.3'))
        self.assertFalse(m('0.0.4', '^0.0.3'))
        self.assertTrue(m('0.9.5', '< 0.10.0, >= 0.9.3'))
        self.assertFalse(m('0.9.2', '< 0.10.0, >= 0.9.3'))
        self.assertTrue(m('1.2.9', '~1.2.3'))
        self.assertFalse(m('1.3.0', '~1.2.3'))
        self.assertTrue(m('0.3.1', '< 0.3.2'))

    def test_advisory_db_and_reviewed_list(self):
        with tempfile.TemporaryDirectory() as d:
            adv = pathlib.Path(d, 'crates', 'smallvec')
            adv.mkdir(parents=True)
            (adv / 'RUSTSEC-2018-0003.md').write_text(
                '```toml\n[advisory]\nid = "RUSTSEC-2018-0003"\npackage = "smallvec"\n\n[versions]\n'
                'patched = [">= 0.6.3", "^0.3.4", "^0.4.5", "^0.5.1"]\nunaffected = ["< 0.3.2"]\n```\n\n# Double free\n')
            (adv / 'RUSTSEC-2099-0001.md').write_text(
                '```toml\n[advisory]\nid = "RUSTSEC-2099-0001"\npackage = "smallvec"\nwithdrawn = "2099-01-01"\n\n[versions]\npatched = []\n```\n# gone\n')
            db = pc.load_advisories(d)
            self.assertEqual(len(db['smallvec']), 1, 'withdrawn advisories are skipped')
            a = db['smallvec'][0]
            self.assertTrue(pc.affected(a, '0.6.0'))
            self.assertTrue(pc.affected(a, '0.4.4'))
            self.assertFalse(pc.affected(a, '0.6.3'))
            self.assertFalse(pc.affected(a, '0.4.5'))
            self.assertFalse(pc.affected(a, '0.3.1'))
            acc = pathlib.Path(d, 'acc.txt')
            acc.write_text('# reviewed\nRUSTSEC-2018-0003 smallvec 0.6.0 | not reachable\n')
            self.assertIn(('RUSTSEC-2018-0003', 'smallvec', '0.6.0'), pc.load_accepted(acc))
            acc.write_text('RUSTSEC-2018-0003 smallvec 0.6.0\n')  # no reason: refused
            with self.assertRaises(SystemExit):
                pc.load_accepted(acc)

    def test_lock_parser(self):
        pk = pc.parse_lock('[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "git+https://x"\n'
                           '[[package]]\nname = "b"\nversion = "2.0.0"\n')
        self.assertEqual(pk[0]['source'], 'git+https://x')
        self.assertNotIn('source', pk[1])


if __name__ == '__main__':
    unittest.main()
