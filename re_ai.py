import os
import shutil

replacements = [
    ("ANTHROPIC", "GEMINI"),
    ("Anthropic", "Gemini"),
    ("anthropic", "gemini"),
    ("claude-sonnet-4-20250514", "gemini-2.5-flash"),
    ("sk-ant-", "AIza"),
    ("claude", "gemini"),
    ("Claude", "Gemini"),
    ("CLAUDE", "GEMINI")
]

ignore_dirs = {'.git', '__pycache__', 'node_modules', 'dist', 'out'}

def process_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return False

    original = content
    for old, new in replacements:
        content = content.replace(old, new)

    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated {filepath}")
        return True
    return False

# Replace text in files
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in ignore_dirs]
    for file in files:
        # Don't replace our script to avoid weirdness
        if file == "re_ai.py": continue
        if file.endswith((".py", ".ts", ".html", ".md", ".json", ".yml", ".txt")):
            process_file(os.path.join(root, file))

# Rename claude_analyzer.py to gemini_analyzer.py
old_file = os.path.join("src", "ai", "claude_analyzer.py")
new_file = os.path.join("src", "ai", "gemini_analyzer.py")
if os.path.exists(old_file):
    os.rename(old_file, new_file)
    print(f"Renamed {old_file} to {new_file}")

print("Replacement complete.")
