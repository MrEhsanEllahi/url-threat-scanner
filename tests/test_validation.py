import unittest

from scan_engine import normalize_and_validate_url


class ValidationTests(unittest.TestCase):
    def test_rejects_email(self):
        normalized, error = normalize_and_validate_url('test@gmail.com')
        self.assertEqual(normalized, '')
        self.assertIn('website URL', error)

    def test_rejects_private_ip(self):
        normalized, error = normalize_and_validate_url('http://10.0.0.1')
        self.assertEqual(normalized, '')
        self.assertIn('Private/local IP', error)

    def test_rejects_invalid_scheme(self):
        normalized, error = normalize_and_validate_url('ftp://example.com')
        self.assertEqual(normalized, '')
        self.assertIn('http/https', error)

    def test_rejects_invalid_port(self):
        normalized, error = normalize_and_validate_url('https://example.com:0')
        self.assertEqual(normalized, '')
        self.assertIn('Invalid port', error)

    def test_accepts_public_domain(self):
        normalized, error = normalize_and_validate_url('example.com')
        self.assertEqual(error, '')
        self.assertTrue(normalized.startswith('https://'))


if __name__ == '__main__':
    unittest.main()
