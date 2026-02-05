import os
import re

MD_PATH = "/Users/tanishq/.gemini/antigravity/brain/240f80fd-2a5c-4047-94e5-7719cf30e028/research_paper.md"
HTML_PATH = "/Users/tanishq/.gemini/antigravity/brain/240f80fd-2a5c-4047-94e5-7719cf30e028/research_paper.html"

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>The Price of Inference - Research Paper</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <style>
        body { 
            font-family: 'Times New Roman', Times, serif; 
            line-height: 1.6; 
            max-width: 850px; 
            margin: 0 auto; 
            padding: 40px; 
            background-color: #fff; 
            color: #1a1a1a;
        }
        h1, h2, h3, h4 { color: #111; margin-top: 1.5em; }
        h1 { text-align: center; font-size: 2.5em; margin-bottom: 0.5em; }
        pre { background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #ddd; }
        code { font-family: 'Courier New', Courier, monospace; }
        .mermaid { text-align: center; margin: 30px 0; }
        blockquote { border-left: 4px solid #ccc; margin: 1.5em 10px; padding: 0.5em 10px; color: #555; }
        img { max-width: 100%; display: block; margin: 20px auto; }
        
        @media print {
            body { padding: 0; max-width: 100%; }
            @page { margin: 2cm; }
            .no-print { display: none; }
        }
    </style>
</head>
<body>

<div id="content"></div>

<!-- Hidden Markdown Source -->
<script type="text/markdown" id="raw-content">
{RAW_CONTENT}
</script>

<script>
    // Initialize Mermaid
    mermaid.initialize({ startOnLoad: false, theme: 'default' });

    // Custom Renderer for Mermaid
    const renderer = new marked.Renderer();
    const originalCode = renderer.code;
    
    renderer.code = function(code, language) {
        if (language === 'mermaid') {
            return '<div class="mermaid">' + code + '</div>';
        }
        return originalCode.call(this, code, language);
    };

    marked.setOptions({ renderer: renderer });

    // Read and Parse Markdown
    const rawMd = document.getElementById('raw-content').textContent;
    document.getElementById('content').innerHTML = marked.parse(rawMd);

    // Initial render of charts
    mermaid.run();
</script>

</body>
</html>
"""

def generate_html():
    if not os.path.exists(MD_PATH):
        print(f"Error: {MD_PATH} not found.")
        return

    with open(MD_PATH, 'r') as f:
        content = f.read()

    # Escape backticks slightly to prevent script injection issues if any? 
    # Actually, inside a script tag it is fine unless it contains </script>
    # We can handle that.
    content = content.replace("</script>", "<\\/script>")

    final_html = TEMPLATE.replace("{RAW_CONTENT}", content)

    with open(HTML_PATH, 'w') as f:
        f.write(final_html)

    print(f"Successfully generated: {HTML_PATH}")

if __name__ == "__main__":
    generate_html()
