import os

def split_html_into_files(input_file, output_dir):
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Read the HTML file
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split content by the separator
    parts = content.split('</pre></td></tr><tr><td><pre>')

    # Process each part
    for part in parts:
        # Clean up the part
        part = part.replace('<html><head><meta http-equiv=\'content-type\' content=\'text/html; charset=UTF-8\'><meta charset=\'UTF-8\'><title>Dataset items</title></head><body><style>body {margin: 0;}table {border-collapse: collapse;border-spacing:0;border: solid 1px #D0D5E9;font-size: 12px;position: relative;}th {position: sticky;top: -1px;background-color: #E0E3F2;}th, td {padding: 5px 5px 5px 5px;border: solid 1px #D0D5E9;color: #242836;text-align: left;}td {vertical-align: top;}th pre, td pre {font-family: monospace !important;margin: 0;padding: 0 0 0 1px;white-space: pre-wrap;}thead tr td, thead tr th {color: #242836;font-size: 12px !important;}tbody > tr:nth-of-type(odd) {background-color: #F8F9FC;}tbody > tr:hover {background-color: #EEF0F8;}</style><table><thead><tr><th><pre>text</pre></th></tr></thead><tr><td><pre>', '')
        part = part.replace('</pre></td></tr></table></body></html>', '')
        
        # Skip empty parts
        if not part.strip():
            continue

        # Get the first line as filename
        lines = part.strip().split('\n')
        if not lines:
            continue

        filename = lines[0].strip()
        # Format filename to use lowercase rio and dots
        filename = filename.replace(' - ', '.')
        filename = filename.replace('-', '.')
        filename = filename.replace('_', '.')
        filename = filename.replace(' ', '.')
        # Ensure it starts with lowercase rio
        if filename.lower().startswith('rio'):
            filename = 'rio' + filename[3:]
        filename = filename.strip('.')
        
        if not filename:
            continue

        # Write content to file
        output_file = os.path.join(output_dir, f"{filename}.txt")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

if __name__ == "__main__":
    input_file = "c:/Users/Azidan/Desktop/AQL/RioBase/RioDocumentation/RioKnowledgeBase.html"
    output_dir = "c:/Users/Azidan/Desktop/AQL/RioBase/RioDocumentation/split_docs"
    split_html_into_files(input_file, output_dir)
    print("Documentation has been split into separate files in the 'split_docs' directory.")
