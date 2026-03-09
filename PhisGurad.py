import re
import tkinter as tk
from tkinter import messagebox, scrolledtext

def analyze_links(email_text):
    score = 0
    flags = []
    links = re.findall(r'https?://[^\s]+', email_text)
    for link in links:
        if "@" in link:
            score += 35
            flags.append(f"CRITICAL: Credential Phishing Link: {link}")
        if "http://" in link:
            score += 15
            flags.append(f"WARNING: Insecure HTTP link: {link}")
    return score, flags

def analyze_content(email_text):
    database = {
        "urgent": {"weight": 25, "category": "Urgency"},
        "verify": {"weight": 15, "category": "Action"},
        "suspended": {"weight": 30, "category": "Threat"},
        "login": {"weight": 10, "category": "Action"},
        "bank": {"weight": 15, "category": "Target"},
        "giftcard": {"weight": 20, "category": "Scam"}
    }
    score = 0
    flags = []
    clean_text = email_text.lower()
    for word, data in database.items():
        if word in clean_text:
            score += data["weight"]
            flags.append(f"FLAG: {data['category']} keyword '{word}' (+{data['weight']})")
    return score, flags

class PhishGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishGuard v1.0")
        self.root.geometry("500x600")
        
        # --- UI Setup ---
        tk.Label(root, text="PhishGuard Scanner", font=("Arial", 14, "bold")).pack(pady=10)
        
        tk.Label(root, text="Paste Email Text:").pack(anchor="w", padx=20)
        self.input_area = scrolledtext.ScrolledText(root, height=10, width=55)
        self.input_area.pack(pady=5, padx=20)
        
        self.btn = tk.Button(root, text="SCAN EMAIL", command=self.run_analysis, 
                             bg="#d35400", fg="white", font=("Arial", 10, "bold"))
        self.btn.pack(pady=10)
        
        tk.Label(root, text="Analysis Results:").pack(anchor="w", padx=20)
        self.output_area = scrolledtext.ScrolledText(root, height=10, width=55, state='disabled', bg="#ecf0f1")
        self.output_area.pack(pady=5, padx=20)
        
        self.score_label = tk.Label(root, text="Risk Score: 0", font=("Arial", 12, "bold"))
        self.score_label.pack(pady=10)

    def run_analysis(self):
        text = self.input_area.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Input Empty", "Please paste an email to scan.")
            return
            
        c_score, c_flags = analyze_content(text)
        l_score, l_flags = analyze_links(text)
        total = c_score + l_score
        
        # Update UI
        self.score_label.config(text=f"Risk Score: {total}", fg="red" if total >= 50 else "green")
        
        self.output_area.config(state='normal')
        self.output_area.delete("1.0", tk.END)
        
        for f in (c_flags + l_flags):
            self.output_area.insert(tk.END, f"• {f}\n")
            
        if not (c_flags + l_flags):
            self.output_area.insert(tk.END, "Clean: No obvious phishing markers found.")
            
        self.output_area.config(state='disabled')

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = PhishGuardApp(root)
        root.mainloop()
    except Exception as e:
        print(f"CRITICAL ERROR: Could not start the GUI. Reason: {e}")
