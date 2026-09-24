import tkinter as tk
from tkinter import messagebox
from analyzer import analyze_password


class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("900x650")
        self.root.minsize(820, 600)

        self.bg = "#07182b"
        self.panel = "#0d2239"
        self.text = "#eef6ff"
        self.muted = "#a9bdd1"
        self.accent = "#21d4a5"

        self.root.configure(bg=self.bg)

        self.password_var = tk.StringVar()
        self.score_var = tk.StringVar(value="0 / 100")
        self.strength_var = tk.StringVar(value="NOT ANALYZED")
        self.entropy_var = tk.StringVar(value="0 bits")

        self.build_ui()

    def build_ui(self):
        title = tk.Label(self.root, text="PASSWORD STRENGTH ANALYZER", bg=self.bg, fg=self.text, font=("Segoe UI", 24, "bold"))
        title.pack(pady=(22, 4))

        subtitle = tk.Label(self.root, text="Analyze password characteristics locally", bg=self.bg, fg=self.muted, font=("Segoe UI", 11))
        subtitle.pack(pady=(0, 18))

        input_panel = tk.Frame(self.root, bg=self.panel, padx=18, pady=18)
        input_panel.pack(fill="x", padx=35)

        tk.Label(input_panel, text="Enter Password:", bg=self.panel, fg=self.text, font=("Segoe UI", 11, "bold")).pack(anchor="w")

        row = tk.Frame(input_panel, bg=self.panel)
        row.pack(fill="x", pady=10)

        self.password_entry = tk.Entry(row, textvariable=self.password_var, show="*", font=("Segoe UI", 13), bg="#102d49", fg=self.text, insertbackground=self.text, relief="flat")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=9)

        self.show_button = tk.Button(row, text="Show", command=self.toggle_password, bg="#193957", fg=self.text, relief="flat", padx=14)
        self.show_button.pack(side="left", padx=(8, 0), ipady=5)

        button_row = tk.Frame(input_panel, bg=self.panel)
        button_row.pack(fill="x")

        tk.Button(button_row, text="ANALYZE PASSWORD", command=self.analyze, bg=self.accent, fg="#06201b", font=("Segoe UI", 10, "bold"), relief="flat", padx=22, pady=9).pack(side="left")
        tk.Button(button_row, text="CLEAR", command=self.clear, bg="#193957", fg=self.text, relief="flat", padx=22, pady=9).pack(side="left", padx=10)

        content = tk.Frame(self.root, bg=self.bg)
        content.pack(fill="both", expand=True, padx=35, pady=18)

        left = tk.Frame(content, bg=self.panel, padx=18, pady=18)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))

        right = tk.Frame(content, bg=self.panel, padx=18, pady=18)
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))

        tk.Label(left, text="Password Strength", bg=self.panel, fg=self.text, font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self.strength_label = tk.Label(left, textvariable=self.strength_var, bg=self.panel, fg=self.accent, font=("Segoe UI", 24, "bold"))
        self.strength_label.pack(pady=(18, 3))
        tk.Label(left, text="Score", bg=self.panel, fg=self.muted, font=("Segoe UI", 10)).pack()
        tk.Label(left, textvariable=self.score_var, bg=self.panel, fg=self.text, font=("Segoe UI", 18, "bold")).pack(pady=(0, 14))
        tk.Label(left, text="Detailed Analysis", bg=self.panel, fg=self.text, font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(8, 5))

        self.details = tk.Text(left, height=10, width=48, bg="#091a2c", fg=self.text, relief="flat", font=("Consolas", 9), state="disabled")
        self.details.pack(fill="both", expand=True)

        tk.Label(right, text="Password Entropy", bg=self.panel, fg=self.text, font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(right, textvariable=self.entropy_var, bg=self.panel, fg=self.accent, font=("Segoe UI", 22, "bold")).pack(anchor="w", pady=(14, 5))
        tk.Label(right, text="Higher estimated entropy generally means a larger search space.", bg=self.panel, fg=self.muted, font=("Segoe UI", 9), wraplength=320, justify="left").pack(anchor="w")
        tk.Label(right, text="Security Tips", bg=self.panel, fg=self.text, font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(28, 8))

        self.tips = tk.Text(right, height=12, width=40, bg="#091a2c", fg=self.text, relief="flat", font=("Segoe UI", 9), state="disabled")
        self.tips.pack(fill="both", expand=True)

        footer = tk.Label(self.root, text="Privacy: password is analyzed in memory and is not saved by this application.", bg=self.bg, fg=self.muted, font=("Segoe UI", 9))
        footer.pack(pady=(0, 12))

    def toggle_password(self):
        if self.password_entry.cget("show") == "*":
            self.password_entry.config(show="")
            self.show_button.config(text="Hide")
        else:
            self.password_entry.config(show="*")
            self.show_button.config(text="Show")

    def analyze(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Missing Password", "Please enter a password.")
            return

        result = analyze_password(password)
        self.score_var.set(f"{result['score']} / 100")
        self.strength_var.set(result["strength"])
        self.entropy_var.set(f"{result['entropy']} bits")

        self.details.config(state="normal")
        self.details.delete("1.0", "end")

        labels = {
            "length": "12+ characters",
            "uppercase": "Uppercase letter",
            "lowercase": "Lowercase letter",
            "number": "Number",
            "special": "Special character",
            "common": "Not a common password",
            "repeated": "No repeated characters",
            "sequential": "No simple sequence",
        }

        for key, label in labels.items():
            mark = "✓" if result["checks"][key] else "✗"
            self.details.insert("end", f"{mark} {label}\n")

        self.details.config(state="disabled")
        self.tips.config(state="normal")
        self.tips.delete("1.0", "end")

        for tip in result["tips"]:
            self.tips.insert("end", f"• {tip}\n\n")

        self.tips.config(state="disabled")

    def clear(self):
        self.password_var.set("")
        self.score_var.set("0 / 100")
        self.strength_var.set("NOT ANALYZED")
        self.entropy_var.set("0 bits")

        for widget in (self.details, self.tips):
            widget.config(state="normal")
            widget.delete("1.0", "end")
            widget.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzerApp(root)
    root.mainloop()
