import unittest

from scan_engine import FEATURE_COLUMNS, build_ml_feature_vector, compute_schema_hash


class FeatureSchemaTests(unittest.TestCase):
    def test_schema_hash_is_stable(self):
        digest = compute_schema_hash(FEATURE_COLUMNS)
        self.assertEqual(len(digest), 64)

    def test_model_vector_contract(self):
        vec = build_ml_feature_vector(
            normalized_url='https://example.com',
            url_lexical={
                'has_ip_host': False,
                'url_length': 20,
                'shortener_hint': False,
                'has_at_symbol': False,
                'double_slash_redirect_hint': False,
                'has_hyphenated_domain': False,
                'subdomain_depth': 1,
                'scheme': 'https',
                'has_non_standard_port': False,
                'https_in_hostname': False,
            },
            page_dom={
                'external_anchor_ratio': 0.1,
                'external_script_ratio': 0.1,
                'external_form_action_ratio': 0.0,
                'mailto_links': 0,
                'statusbar_signal_count': 0,
                'right_click_blocked': False,
                'popup_signal_count': 0,
                'iframe_count': 0,
                'anchor_count': 5,
                'external_favicon_ratio': 0.0,
            },
            domain_host={
                'domain_age_days': 500,
                'domain_expires_in_days': 700,
                'whois_available': True,
                'dns_resolved': True,
            },
            reachability={'state': 'reachable'},
            redirect_check={'hops': []},
        )
        self.assertEqual(set(vec.keys()), set(FEATURE_COLUMNS))
        self.assertTrue(all(isinstance(v, int) for v in vec.values()))


if __name__ == '__main__':
    unittest.main()
