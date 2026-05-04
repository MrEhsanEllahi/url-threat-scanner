import unittest
from unittest.mock import patch

import app as app_module


class ScanApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    def test_api_scan_invalid_url(self):
        response = self.client.post('/api/scan', json={'url': 'test@gmail.com'})
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn('validation', payload)
        self.assertIn('reachability', payload)
        self.assertIn('features', payload)
        self.assertIn('prediction', payload)
        self.assertIn('confidence', payload)
        self.assertIn('top_signals', payload)
        self.assertIn('errors', payload)

    def test_api_scan_contract_valid(self):
        fake = {
            'validation': {'ok': True, 'normalized_url': 'https://example.com', 'error': ''},
            'reachability': {'state': 'reachable', 'label': 'Reachable', 'detail': '', 'engine': 'chrome', 'final_url': 'https://example.com', 'title': 'Example', 'load_time': '0.3s', 'redirect_hops': 0},
            'features': {'status': 'full', 'note': '', 'url_lexical': {}, 'page_dom': {}, 'domain_host': {}, 'model_vector': {}, 'schema_hash': 'abc'},
            'prediction': {'status': 'ok', 'verdict': 'Legitimate', 'risk_score': 2.0, 'confidence': 98.0, 'phishing_probability': 0.02, 'safe_probability': 0.98, 'model_version': '1.0', 'top_signals': [], 'rule_notes': [], 'error': ''},
            'confidence': 98.0,
            'top_signals': [],
            'errors': [],
        }
        with patch.object(app_module, 'run_canonical_scan', return_value=fake):
            response = self.client.post('/api/scan', json={'url': 'example.com'})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['validation']['ok'])
        self.assertEqual(payload['prediction']['verdict'], 'Legitimate')


if __name__ == '__main__':
    unittest.main()
