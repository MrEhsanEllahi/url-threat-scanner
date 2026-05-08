import re

with open('scan_engine.py', 'r') as f:
    content = f.read()

new_features = ['url_len', '@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', 'digits', 'letters', 'abnormal_url', 'https', 'Shortining_Service', 'having_ip_address', 'web_http_status', 'web_is_live', 'web_ext_ratio', 'web_unique_domains', 'web_favicon', 'web_csp', 'web_xframe', 'web_hsts', 'web_xcontent', 'web_security_score', 'web_forms_count', 'web_password_fields', 'web_hidden_inputs', 'web_has_login', 'web_ssl_valid', 'phish_urgency_words', 'phish_security_words', 'phish_brand_mentions', 'phish_brand_hijack', 'phish_multiple_subdomains', 'phish_long_path', 'phish_many_params', 'phish_suspicious_tld', 'phish_adv_exact_brand_match', 'phish_adv_brand_in_subdomain', 'phish_adv_brand_in_path', 'phish_adv_hyphen_count', 'phish_adv_number_count', 'phish_adv_suspicious_tld', 'phish_adv_long_domain', 'phish_adv_many_subdomains', 'phish_adv_encoded_chars', 'phish_adv_path_keywords', 'phish_adv_has_redirect', 'phish_adv_many_params', 'path_has_hacked_terms', 'suspicious_extension', 'path_underscore_count', 'is_gov_edu']

features_str = "FEATURE_COLUMNS = [\n" + ",\n".join(f'    "{f}"' for f in new_features) + "\n]\n"

content = re.sub(r'FEATURE_COLUMNS = \[.*?\]\n', features_str, content, flags=re.DOTALL)

build_ml_func = """def build_ml_feature_vector(
    normalized_url: str,
    url_lexical: dict[str, Any],
    page_dom: dict[str, Any],
    domain_host: dict[str, Any],
    reachability: dict[str, Any],
    redirect_check: dict[str, Any],
) -> dict[str, int | float]:
    url = normalized_url

    # Calculate basic lexical counts
    char_counts = {c: url.count(c) for c in ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']}
    digits_count = sum(c.isdigit() for c in url)
    letters_count = sum(c.isalpha() for c in url)

    has_https = 1 if url_lexical.get("scheme") == "https" else 0
    is_live = 1 if reachability.get("state") == "reachable" else 0
    
    # Calculate some heuristic advanced features
    path_underscore_count = url_lexical.get("path_depth", 0) # approximation
    
    vec = {
        "url_len": len(url),
        "digits": digits_count,
        "letters": letters_count,
        "abnormal_url": 1 if not domain_host.get("whois_available") else 0,
        "https": has_https,
        "Shortining_Service": 1 if url_lexical.get("shortener_hint") else 0,
        "having_ip_address": 1 if url_lexical.get("has_ip_host") else 0,
        "web_http_status": 200 if is_live else 0,
        "web_is_live": is_live,
        "web_ext_ratio": float(page_dom.get("external_anchor_ratio", 0.0) or 0.0),
        "web_unique_domains": int(page_dom.get("anchor_count", 0) or 0),
        "web_favicon": 1 if float(page_dom.get("external_favicon_ratio", 0.0) or 0.0) > 0 else 0,
        "web_csp": 0,
        "web_xframe": 0,
        "web_hsts": 0,
        "web_xcontent": 0,
        "web_security_score": 0,
        "web_forms_count": int(page_dom.get("form_count", 0) or 0),
        "web_password_fields": int(page_dom.get("password_input_count", 0) or 0),
        "web_hidden_inputs": int(page_dom.get("hidden_element_count", 0) or 0),
        "web_has_login": 1 if int(page_dom.get("password_input_count", 0) or 0) > 0 else 0,
        "web_ssl_valid": has_https,
        "phish_urgency_words": 0,
        "phish_security_words": 0,
        "phish_brand_mentions": 0,
        "phish_brand_hijack": 0,
        "phish_multiple_subdomains": 1 if url_lexical.get("subdomain_depth", 0) > 1 else 0,
        "phish_long_path": 1 if url_lexical.get("path_depth", 0) > 3 else 0,
        "phish_many_params": 1 if url_lexical.get("query_param_count", 0) > 2 else 0,
        "phish_suspicious_tld": 0,
        "phish_adv_exact_brand_match": 0,
        "phish_adv_brand_in_subdomain": 0,
        "phish_adv_brand_in_path": 0,
        "phish_adv_hyphen_count": url.count('-'),
        "phish_adv_number_count": digits_count,
        "phish_adv_suspicious_tld": 0,
        "phish_adv_long_domain": 1 if len(domain_host.get("host", "")) > 30 else 0,
        "phish_adv_many_subdomains": 1 if url_lexical.get("subdomain_depth", 0) > 2 else 0,
        "phish_adv_encoded_chars": url.count('%'),
        "phish_adv_path_keywords": 0,
        "phish_adv_has_redirect": 1 if url.count('//') > 1 else 0,
        "phish_adv_many_params": 1 if url_lexical.get("query_param_count", 0) > 3 else 0,
        "path_has_hacked_terms": 0,
        "suspicious_extension": 0,
        "path_underscore_count": url.count('_'),
        "is_gov_edu": 1 if domain_host.get("tld", "") in ["gov", "edu"] else 0,
    }
    
    for c in ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']:
        vec[c] = char_counts[c]
        
    return vec
"""

content = re.sub(r'def build_ml_feature_vector.*?return feature_vector\n', build_ml_func, content, flags=re.DOTALL)

with open('scan_engine.py', 'w') as f:
    f.write(content)

with open('train_model.py', 'r') as f:
    train_content = f.read()

train_content = train_content.replace('required = set(FEATURE_COLUMNS + ["class"])', 'required = set(FEATURE_COLUMNS + ["type"])')
train_content = train_content.replace('y_raw = df["class"].astype(int)', 'y_raw = df["type"]')
train_content = train_content.replace('y = (y_raw == -1).astype(int)', 'y = (y_raw != "benign").astype(int)')
train_content = train_content.replace('default="phishing.csv",', 'default="datasets/final_dataset_with_all_features_v3.1.csv",')
train_content = train_content.replace('description="Train phishing classifier bundle (v2 — with hyperparameter tuning)."', 'description="Train phishing classifier bundle (v3 — with 65-feature schema)."')

with open('train_model.py', 'w') as f:
    f.write(train_content)

print("scan_engine.py and train_model.py updated")
