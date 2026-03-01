import re

def create_keyword_database():
    database = {
        "urgent": {"weight": 25, "category": "Urgency"},
        "verify": {"weight": 15, "category": "Action"},
        "suspended": {"weight": 30, "category": "Threat"},
        "login": {"weight": 10, "category": "Action"},
        "bank": {"weight": 15, "category": "Target"},
        "giftcard": {"weight": 20, "category": "Scam"}
    }
    return database
def analyze_links(email_text):
    score = 0
    flags = []
    
    links = re.findall(r'https?://[^\s]+', email_text)
    
    for link in links:
        if "@" in link:
            score += 35
            flags.append(f"CRITICAL: Credential Phishing Link found: {link}")

        if "http://" in link:
            score += 15
            flags.append(f"WARNING: Insecure HTTP link: {link}")
            
    return score, flags

def analyze_content(email_text, kw_database):
    score = 0
    flags = []
    clean_text = email_text.lower()
    
    for word, data in kw_database.items():
        if word in clean_text:
            score += data["weight"]
            flags.append(f"FLAG: {data['category']} keyword '{word}' detected (+{data['weight']})")
            
    return score, flags
def run_phishing_scanner(email_content):
    db = create_keyword_database()
    
    print("="*40)
    print("      PHISHGUARD SECURITY SCANNER      ")
    print("="*40)

    content_score, content_flags = analyze_content(email_content, db)
    link_score, link_flags = analyze_links(email_content)
    
    total_score = content_score + link_score
    all_flags = content_flags + link_flags
    
    if total_score >= 60:
        verdict = "🚨 DANGER: HIGH PROBABILITY OF PHISHING"
    elif 25 <= total_score < 60:
        verdict = "⚠️ WARNING: SUSPICIOUS CONTENT DETECTED"
    else:
        verdict = "✅ SAFE: NO IMMEDIATE THREATS FOUND"
        
    print(f"VERDICT: {verdict}")
    print(f"TOTAL RISK SCORE: {total_score}")
    print("-" * 20)
    print("DETECTION DETAILS:")
    for f in all_flags:
        print(f" - {f}")
    
    return total_score
def run_quality_tests():
    print("\n[SYSTEM] Running Code Quality Tests...")
    
    test_1 = "Urgent! Your bank account is suspended. Login at http://fake.com"
    score_1 = run_phishing_scanner(test_1)
    assert score_1 >= 50, "Test 1 Failed: High risk not detected"
    
    test_2 = "Hey, do you want to grab coffee later?"
    score_2 = run_phishing_scanner(test_2)
    assert score_2 < 20, "Test 2 Failed: Safe email flagged incorrectly"
    
    print("\n[RESULT] All Quality Tests Passed Successfully.")

if __name__ == "__main__":
    sample_email = """
    From: security@secure-bank.net
    Subject: Action Required: Your account is suspended!
    Please verify your identity immediately by clicking here: 
    http://login-verify.com@suspicious-site.biz/login
    """
    
    run_phishing_scanner(sample_email)
    run_quality_tests()