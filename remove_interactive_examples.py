import os
import re

def remove_interactive_examples(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Pattern to match everything from "Interactive example" to "Constructor"
    # Using non-greedy match .*? to avoid overshooting to a later "Constructor"
    pattern = r'\nInteractive example.*?\nConstructor'
    
    # Replace the matched pattern with just "\nConstructor"
    new_content = re.sub(pattern, '\nConstructor', content, flags=re.DOTALL)
    
    # Only write if changes were made
    if new_content != content:
        print(f"Removing interactive examples from {os.path.basename(file_path)}")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    doc_dir = os.path.join(os.path.dirname(script_dir), 'RioDocumentation')
    
    # Process all .txt files in the RioDocumentation directory
    for filename in os.listdir(doc_dir):
        if filename.endswith('.txt'):
            file_path = os.path.join(doc_dir, filename)
            remove_interactive_examples(file_path)

if __name__ == '__main__':
    main()
