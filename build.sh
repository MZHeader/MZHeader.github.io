#!/bin/bash
set -e

mkdir -p _site/posts

# Copy static assets
cp -r assets _site/ 2>/dev/null || true
cp -r css _site/ 2>/dev/null || true
cp -r js _site/ 2>/dev/null || true
cp -r samples _site/ 2>/dev/null || true
cp favicon.ico _site/ 2>/dev/null || true
cp CNAME _site/ 2>/dev/null || true

SHARED_CSS='
    * { box-sizing: border-box; }
    body {
      background: #1e1e1e;
      color: #dcdcdc;
      font-family: "Segoe UI", "Roboto", sans-serif;
      padding: 2rem;
      line-height: 1.6;
      max-width: 900px;
      margin: 0 auto;
    }
    h1, h2, h3, h4 { color: #5625be; }
    a { color: #5625be; text-decoration: none; }
    a:hover { text-decoration: underline; color: #50fa7b; }
    pre code {
      display: block;
      padding: 1em;
      background: #2d2d2d;
      color: #f8f8f2;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.95rem;
      font-family: "Fira Code", "Consolas", monospace;
      box-shadow: 0 0 8px #00000080;
      border: 1px solid #444;
    }
    code {
      font-family: "Fira Code", "Consolas", monospace;
      background: #2d2d2d;
      padding: 0.1em 0.3em;
      border-radius: 3px;
      font-size: 0.9em;
    }
    img { max-width: 100%; border-radius: 4px; }
    .back-link {
      display: inline-block;
      margin-bottom: 2rem;
      color: #8be9fd;
      font-size: 0.9rem;
    }
    .post-meta { color: #888; font-size: 0.85rem; margin-bottom: 2rem; }
'

HLJS_HEAD='
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/base16/dracula.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script>hljs.highlightAll();</script>
'

posts_list_html=""

for post in $(ls _posts/*.md | sort -r); do
    filename=$(basename "$post" .md)
    date_str="${filename:0:10}"
    slug="${filename:11}"

    formatted_date=$(date -d "$date_str" "+%b %-d, %Y" 2>/dev/null || date -j -f "%Y-%m-%d" "$date_str" "+%b %-d, %Y")

    description=$(awk 'BEGIN{f=0} /^---/{f++; next} f==1 && /^description:/{sub(/^description: */, ""); gsub(/^"|"$/, ""); print; exit}' "$post")
    title=$(grep "^## " "$post" | head -1 | sed 's/^## //')
    [ -z "$title" ] && title="$slug"

    body=$(pandoc "$post" \
        --from markdown+yaml_metadata_block \
        --to html \
        --syntax-highlighting=none)

    # Write post header (variables expanded)
    cat > "_site/posts/${slug}.html" << ENDHEADER
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title} — Malware Under the Microscope</title>
  ${HLJS_HEAD}
  <style>${SHARED_CSS}</style>
</head>
<body>
  <a class="back-link" href="/">&larr; Back to home</a>
  <article>
    <div class="post-meta">${formatted_date}</div>
ENDHEADER

    # Append body safely (no variable expansion on content)
    printf '%s\n' "$body" >> "_site/posts/${slug}.html"

    # Append footer
    cat >> "_site/posts/${slug}.html" << 'ENDFOOTER'
  </article>
</body>
</html>
ENDFOOTER

    posts_list_html+="
    <li>
      <a href=\"/posts/${slug}.html\">${title}</a>
      $([ -n "$description" ] && echo "<p class=\"post-description\">${description}</p>")
      <span class=\"post-date\"> &mdash; ${formatted_date}</span>
    </li>"

    echo "Built: posts/${slug}.html"
done

# Generate index.html
cat > "_site/index.html" << ENDINDEX
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Malware Under the Microscope</title>
  ${HLJS_HEAD}
  <style>
    ${SHARED_CSS}
    header {
      border-bottom: 1px solid #333;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
    }
    header p { color: #bbbbbb; max-width: 70ch; }
    .normal-link { color: #8be9fd !important; }
    pre {
      font-family: monospace;
      color: #ff79c6;
      text-align: center;
      background: transparent;
      border: none;
      box-shadow: none;
      padding: 0;
      font-size: 0.75rem;
    }
    ul { list-style: none; padding: 0; }
    li { margin-bottom: 1.25rem; }
    .post-description { color: #aaa; margin: 0.25rem 0 0 0; font-size: 0.9rem; }
    .post-date { color: #888; font-size: 0.85rem; }
  </style>
</head>
<body>

<header>
  <h1>Malware Under the Microscope 🔍</h1>
  <pre>
 __  __ ______
|  \/  |___  /
| |\/| |  / /
| |  | | / /__
|_|  |_|/____|
 MZ HEADER
</pre>
  <p>
    Hi, I'm Liam, a Security Researcher at <strong>CrowdStrike</strong>. This is my personal blog where I break down real-world malware samples with practical techniques &mdash; from unpacking and deobfuscation to debugging, disassembly, and memory forensics.
  </p>
  <p>
    I use tools that are freely available, most of which come pre-installed on <strong>FLARE VM</strong>, so you can follow along without extra setup.
  </p>
  <p>
    All samples referenced are publically available on
    <a class="normal-link" href="https://www.virustotal.com/" target="_blank">VirusTotal</a> and
    <a class="normal-link" href="https://bazaar.abuse.ch/" target="_blank">MalwareBazaar</a>
    and you can also grab them from my <a class="normal-link" href="https://github.com/MZHeader/MZHeader.github.io/tree/main/samples" target="_blank">repo</a>.
  </p>
</header>

<h1>Write-ups</h1>
<ul>
${posts_list_html}
</ul>

</body>
</html>
ENDINDEX

echo "Built: index.html"
echo "Done. Site is in _site/"
