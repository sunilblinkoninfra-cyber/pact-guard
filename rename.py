import os
import sys

EXTENSIONS = {".py", ".md", ".html", ".yml", ".json", ".pact", ".txt", ".js", ".css"}
EXCLUDE_DIRS = {".git", ".github_archive", "__pycache__", "venv"}

replacements = [
    ("Pact Sentinel", "PactGuard"),
    ("pact-sentinel", "pact-guard"),
    ("PactSentinel", "PactGuard"),
    ("PACT SENTINEL", "PACT GUARD"),
    ("pact_sentinel", "pact_guard"),
    ("Pact sentinel", "PactGuard")
]

target_dir = sys.argv[1] if len(sys.argv) > 1 else "."

modified_files = 0

for root, dirs, files in os.walk(target_dir):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for file in files:
        if not any(file.endswith(ext) for ext in EXTENSIONS):
            continue
            
        filepath = os.path.join(root, file)
        
        if "rename.py" in file:
            continue
            
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            try:
                with open(filepath, "r") as f:
                    content = f.read()
            except Exception:
                continue
            
        new_content = content
        for old, new in replacements:
            new_content = new_content.replace(old, new)
            
        if new_content != content:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"Updated: {filepath}")
            modified_files += 1

print(f"Replaced text in {modified_files} files.")
