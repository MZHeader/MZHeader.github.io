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
      border: 1px solid rgba(86, 37, 190, 0.4);
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
post_js_data="const postData = {};"
post_idx=0

for post in $(ls _posts/*.md | sort -r); do
    post_idx=$((post_idx + 1))
    idx=$(printf "%03d" $post_idx)
    filename=$(basename "$post" .md)
    date_str="${filename:0:10}"
    slug="${filename:11}"

    formatted_date=$(date -d "$date_str" "+%b %-d, %Y" 2>/dev/null || date -j -f "%Y-%m-%d" "$date_str" "+%b %-d, %Y")

    description=$(awk 'BEGIN{f=0} /^---/{f++; next} f==1 && /^description:/{sub(/^description: */, ""); gsub(/^"|"$/, ""); print; exit}' "$post")
    title=$(grep "^## " "$post" | head -1 | sed 's/^## //')
    [ -z "$title" ] && title="$slug"

    body=$(pandoc "$post" \
        --from markdown+yaml_metadata_block-implicit_figures \
        --to html \
        --no-highlight)

    # Write post header (variables expanded)
    cat > "_site/posts/${slug}.html" << ENDHEADER
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title} — Malware Under the Microscope</title>
  ${HLJS_HEAD}
  <style>
    ${SHARED_CSS}

    /* Scanline + vignette as body background layers */
    body {
      background-color: #1e1e1e;
      background-image:
        radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.45) 100%),
        repeating-linear-gradient(
          0deg,
          transparent,
          transparent 2px,
          rgba(0, 0, 0, 0.06) 2px,
          rgba(0, 0, 0, 0.06) 4px
        );
    }

    .post-nav {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 2.5rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid #2a2a3a;
    }
    .back-link {
      color: #50fa7b;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.85rem;
      text-shadow: 0 0 6px rgba(80, 250, 123, 0.3);
    }
    .back-link:hover { text-decoration: none; text-shadow: 0 0 10px rgba(80, 250, 123, 0.6); }
    .post-meta {
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.78rem;
      color: #555;
      letter-spacing: 0.03em;
    }

    /* Post title - first h2 */
    article h2:first-of-type {
      font-size: 1.9rem;
      color: #7c4dff;
      text-shadow: 0 0 16px rgba(124, 77, 255, 0.5), 0 0 32px rgba(124, 77, 255, 0.2);
      border-bottom: 1px solid #2a2a3a;
      padding-bottom: 0.5rem;
      margin-bottom: 1.5rem;
    }
    /* Section headings */
    article h2 {
      font-size: 1.2rem;
      color: #8be9fd;
      border-left: 3px solid #5625be;
      padding-left: 0.75rem;
      margin-top: 2rem;
    }
    article h3 {
      font-size: 1rem;
      color: #bd93f9;
      border-left: 2px solid #444;
      padding-left: 0.6rem;
      margin-top: 1.5rem;
    }

    article { max-width: 100%; }
  </style>
</head>
<body>
  <div class="post-nav">
    <a class="back-link" href="/">&larr; cd ..</a>
    <span class="post-meta">${formatted_date}</span>
  </div>
  <article>
ENDHEADER

    # Append body safely (no variable expansion on content)
    printf '%s\n' "$body" >> "_site/posts/${slug}.html"

    # Append footer
    cat >> "_site/posts/${slug}.html" << 'ENDFOOTER'
  </article>
</body>
</html>
ENDFOOTER

    # Encode first 8 chars of title as hex bytes (compact hex column)
    title_hex=""
    for ((i=0; i<8; i++)); do
        if [ $i -lt ${#title} ]; then
            c="${title:$i:1}"
            hb=$(printf '%02X' "'$c" 2>/dev/null || printf '3F')
        else
            hb="00"
        fi
        title_hex+="${hb} "
        [ $i -eq 3 ] && title_hex+=" "
    done
    title_hex="${title_hex% }"

    # Decoded column shows full title (no truncation)
    decoded="${title}"

    offset=$(printf '%08X' $(( (post_idx - 1) * 8 )) )

    # Escape for JS string (basic)
    title_js=$(echo "$title" | sed "s/\\\\/\\\\\\\\/g; s/'/\\\\'/g")
    desc_js=$(echo "$description" | sed "s/\\\\/\\\\\\\\/g; s/'/\\\\'/g")

    post_js_data+="
postData['post-${post_idx}'] = {slug: '/posts/${slug}.html', title: '${title_js}', desc: '${desc_js}', date: '${date_str}'};"

    posts_list_html+="
      <div class=\"hex-row post-entry\" id=\"post-${post_idx}\" onclick=\"window.location='/posts/${slug}.html'\">
        <span class=\"hex-addr\">${offset}</span>
        <span class=\"hex-bytes post-hex\">${title_hex}</span>
        <span class=\"hex-ascii\"><span class=\"ascii-vis post-decoded\">${decoded}</span></span>
      </div>"

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

    /* Scanline + vignette as body background layers */
    body {
      background-color: #1e1e1e;
      background-image:
        radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.45) 100%),
        repeating-linear-gradient(
          0deg,
          transparent,
          transparent 2px,
          rgba(0, 0, 0, 0.06) 2px,
          rgba(0, 0, 0, 0.06) 4px
        );
    }

    header {
      border: none;
      border-radius: 0;
      margin-bottom: 2.5rem;
      padding: 0;
      text-align: center;
      position: relative;
      background: transparent;
      box-shadow: none;
    }
    header p { color: #bbbbbb; max-width: 70ch; margin: 0.5rem auto; text-align: left; }
    .normal-link { color: #8be9fd !important; }

    .site-title {
      font-size: 2rem;
      font-family: "Fira Code", "Consolas", monospace;
      color: #5625be;
      text-shadow: 0 0 12px #5625be80;
      animation: glitch 6s infinite;
      margin-bottom: 0;
    }
    @keyframes glitch {
      0%, 88%, 100% { text-shadow: 0 0 12px #5625be80; transform: translate(0); }
      90% { text-shadow: -2px 0 #ff79c6, 2px 0 #8be9fd; transform: translate(-1px, 0); }
      92% { text-shadow: 2px 0 #ff79c6, -2px 0 #8be9fd; transform: translate(1px, 0); }
      94% { text-shadow: -1px 0 #ff79c6; transform: translate(-1px, 0); }
      96% { text-shadow: 1px 0 #8be9fd; transform: translate(1px, 0); }
      98% { text-shadow: 0 0 12px #5625be80; transform: translate(0); }
    }

    /* Hex editor panel */
    .hex-editor {
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.85rem;
      line-height: 1.8;
      letter-spacing: 0.03em;
      text-align: left;
      margin: 1.5rem auto 0;
      max-width: 900px;
      position: relative;
    }
    .hex-editor-toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.45rem 1rem;
      background: #161620;
      border: 1px solid #2a2a3a;
      border-bottom: none;
      border-radius: 6px 6px 0 0;
      font-size: 0.78rem;
      color: #555;
    }
    .hex-editor-toolbar .toolbar-title { color: #5625be; font-weight: 600; }
    .hex-editor-toolbar .toolbar-info { color: #444; }
    .hex-editor-body {
      background: rgba(10, 10, 16, 0.7);
      border: 1px solid #2a2a3a;
      border-radius: 0 0 6px 6px;
      padding: 0.6rem 0;
      overflow-x: auto;
    }
    .hex-editor-colheader {
      display: flex;
      padding: 0 1rem 0.4rem;
      border-bottom: 1px solid #222233;
      margin-bottom: 0.3rem;
      color: #3a3a55;
      font-size: 0.72rem;
      user-select: none;
    }
    .hex-editor-colheader .col-offset { width: 5.5em; flex-shrink: 0; }
    .hex-editor-colheader .col-hex { width: 14em; flex-shrink: 0; }
    .hex-editor-colheader .col-ascii { flex: 1; padding-left: 1.2em; }
    .hex-row { display: flex; padding: 0.15rem 1rem; transition: background 0.1s ease; }
    .hex-row:hover { background: rgba(86, 37, 190, 0.06); }
    .hex-row .hex-addr { width: 5.5em; flex-shrink: 0; color: #3a3a55; user-select: none; }
    .hex-row .hex-bytes { width: 14em; flex-shrink: 0; color: #3a3a55; font-size: 0.78rem; opacity: 0.7; }
    .hex-row .hex-ascii { flex: 1; padding-left: 1.2em; color: #888; }
    .hex-row .hex-ascii .ascii-vis { color: #888; }

    /* PE .text section bio block */
    .pe-section {
      text-align: left;
      margin: 2rem auto 0;
      max-width: 900px;
      font-family: "Fira Code", "Consolas", monospace;
    }
    .pe-section-toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.45rem 1rem;
      background: #161620;
      border: 1px solid #2a2a3a;
      border-bottom: none;
      border-radius: 6px 6px 0 0;
      font-size: 0.78rem;
      color: #555;
    }
    .pe-section-toolbar .pe-section-name { color: #ff79c6; font-weight: 600; }
    .pe-section-toolbar .pe-section-flags { color: #444; font-size: 0.72rem; }
    .pe-section-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.2rem 1.8rem;
      padding: 0.4rem 1rem;
      background: rgba(10, 10, 16, 0.7);
      border-left: 1px solid #2a2a3a;
      border-right: 1px solid #2a2a3a;
      font-size: 0.72rem;
      color: #3a3a55;
    }
    .pe-section-meta span { white-space: nowrap; }
    .pe-section-meta .meta-label { color: #3a3a55; }
    .pe-section-meta .meta-value { color: #50fa7b; }
    .pe-section-body {
      background: rgba(10, 10, 16, 0.7);
      border: 1px solid #2a2a3a;
      border-top: 1px solid #222233;
      border-radius: 0 0 6px 6px;
      padding: 0.8rem 0;
    }
    .pe-disasm-row {
      display: flex;
      padding: 0.3rem 1rem;
      line-height: 1.7;
      transition: background 0.1s ease;
    }
    .pe-disasm-row:hover { background: rgba(86, 37, 190, 0.06); }
    .pe-gutter {
      width: 7em;
      flex-shrink: 0;
      color: #3a3a55;
      font-size: 0.78rem;
      user-select: none;
      padding-top: 0.15em;
    }
    .pe-instr {
      color: #5625be;
      width: 3.5em;
      flex-shrink: 0;
      font-size: 0.82rem;
      user-select: none;
      padding-top: 0.15em;
    }
    .pe-operand {
      flex: 1;
      color: #dcdcdc;
      font-family: "Segoe UI", "Roboto", sans-serif;
      font-size: 0.92rem;
      line-height: 1.65;
    }
    .pe-operand strong { color: #ff79c6; }
    .pe-operand a { color: #8be9fd !important; }
    .pe-operand a:hover { color: #50fa7b !important; }
    .pe-comment { display: flex; padding: 0.15rem 1rem; }
    .pe-comment-gutter { width: 7em; flex-shrink: 0; }
    .pe-comment-text { color: #3a3a55; font-size: 0.75rem; font-style: italic; }

    .section-heading {
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 1.1rem;
      color: #8be9fd;
      margin-bottom: 1.5rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid #2a2a3a;
      text-shadow: 0 0 6px rgba(139, 233, 253, 0.2);
    }
    .section-heading .prompt {
      color: #50fa7b;
      margin-right: 0.5em;
    }

    .status-bar {
      position: fixed;
      bottom: 0;
      right: 0;
      padding: 0.3rem 1rem;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.82rem;
      color: #50fa7b;
      background: rgba(18, 18, 24, 0.95);
      border-top: 1px solid #2a2a3a;
      border-left: 1px solid #2a2a3a;
      border-radius: 4px 0 0 0;
      opacity: 0;
      transition: opacity 0.15s ease;
      pointer-events: none;
      z-index: 100;
    }
    .status-bar.visible { opacity: 1; }
    .status-bar .cmd-prompt { color: #5625be; margin-right: 0.5em; }

    .post-entry {
      cursor: pointer;
      transition: background 0.1s ease, border-left-color 0.1s ease;
      border-left: 2px solid transparent;
    }
    .post-entry .post-decoded {
      color: #aaa;
      font-size: 0.88rem;
    }
    .post-entry:hover, .post-entry.active {
      background: rgba(86, 37, 190, 0.09);
      border-left-color: #5625be;
    }
    .post-entry:hover .post-hex, .post-entry.active .post-hex { color: #5a5a8a; opacity: 1; }
    .post-entry:hover .post-decoded, .post-entry.active .post-decoded { color: #ff79c6; text-shadow: 0 0 8px rgba(255,121,198,0.3); }
    .post-entry:hover .hex-addr, .post-entry.active .hex-addr { color: #5625be; }

    .hex-info-panel {
      display: flex;
      align-items: flex-start;
      gap: 0.75rem;
      padding: 0.6rem 1rem;
      border-top: 1px solid #222233;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.82rem;
      min-height: 3.2rem;
      background: rgba(10, 10, 16, 0.5);
      border-radius: 0 0 6px 6px;
    }
    .hex-info-prompt { color: #3a3a55; user-select: none; flex-shrink: 0; padding-top: 0.05rem; }
    .hex-info-content { flex: 1; }
    .hex-info-title { color: #555; transition: color 0.15s ease; }
    .hex-info-panel.has-content .hex-info-title { color: #dcdcdc; font-weight: 600; }
    .hex-info-desc { color: #666; font-family: "Segoe UI", "Roboto", sans-serif; font-size: 0.78rem; margin-top: 0.25rem; line-height: 1.5; }
  </style>
</head>
<body>

<header>
  <h1 class="site-title">Malware Under the Microscope</h1>

  <div class="pe-section">
    <div class="pe-section-toolbar">
      <span class="pe-section-name">.text</span>
      <span class="pe-section-flags">IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ</span>
    </div>
    <div class="pe-section-meta">
      <span><span class="meta-label">VirtualSize:</span> <span class="meta-value">0x00000340</span></span>
      <span><span class="meta-label">VirtualAddress:</span> <span class="meta-value">0x00001000</span></span>
      <span><span class="meta-label">SizeOfRawData:</span> <span class="meta-value">0x00000400</span></span>
      <span><span class="meta-label">Characteristics:</span> <span class="meta-value">0x60000020</span></span>
    </div>
    <div class="pe-section-body">
      <div class="pe-comment">
        <span class="pe-comment-gutter"></span>
        <span class="pe-comment-text">;; Liam &mdash; Security Researcher @ CrowdStrike</span>
      </div>
      <div class="pe-disasm-row">
        <span class="pe-gutter">.text:0000</span>
        <span class="pe-instr">push</span>
        <span class="pe-operand">Hi, I'm Liam, a Security Researcher at <strong>CrowdStrike</strong>. This is my personal blog where I break down real-world malware samples with practical techniques &mdash; from unpacking and deobfuscation to debugging, disassembly, and memory forensics.</span>
      </div>
      <div class="pe-comment">
        <span class="pe-comment-gutter"></span>
        <span class="pe-comment-text">;; tooling</span>
      </div>
      <div class="pe-disasm-row">
        <span class="pe-gutter">.text:0028</span>
        <span class="pe-instr">lea</span>
        <span class="pe-operand">I use tools that are freely available, most of which come pre-installed on <strong>FLARE VM</strong>, so you can follow along without extra setup.</span>
      </div>
      <div class="pe-comment">
        <span class="pe-comment-gutter"></span>
        <span class="pe-comment-text">;; sample sources</span>
      </div>
      <div class="pe-disasm-row">
        <span class="pe-gutter">.text:0050</span>
        <span class="pe-instr">mov</span>
        <span class="pe-operand">All samples referenced are publically available on <a href="https://www.virustotal.com/" target="_blank">VirusTotal</a> and <a href="https://bazaar.abuse.ch/" target="_blank">MalwareBazaar</a> and you can also grab them from my <a href="https://github.com/MZHeader/MZHeader.github.io/tree/main/samples" target="_blank">repo</a>.</span>
      </div>
    </div>
  </div>
</header>

<div class="hex-editor" id="writeUpsHex">
  <div class="hex-editor-toolbar">
    <span class="toolbar-title">write-ups.db</span>
    <span class="toolbar-info">11 entries &mdash; click to open</span>
  </div>
  <div class="hex-editor-body">
    <div class="hex-editor-colheader">
      <span class="col-offset">Offset</span>
      <span class="col-hex">00 01 02 03  04 05 06 07</span>
      <span class="col-ascii">Decoded text</span>
    </div>
${posts_list_html}
  </div>
  <div class="hex-info-panel" id="hexInfoPanel">
    <span class="hex-info-prompt">;;</span>
    <div class="hex-info-content">
      <div class="hex-info-title" id="hexInfoTitle">hover an entry to inspect</div>
      <div class="hex-info-desc" id="hexInfoDesc"></div>
    </div>
  </div>
</div>

<div class="status-bar" id="statusBar">
  <span class="cmd-prompt">\$</span><span id="statusCmd"></span>
</div>

<script>
  ${post_js_data}

  const bar = document.getElementById('statusBar');
  const cmd = document.getElementById('statusCmd');
  const infoTitle = document.getElementById('hexInfoTitle');
  const infoDesc = document.getElementById('hexInfoDesc');
  const infoPanel = document.getElementById('hexInfoPanel');

  document.querySelectorAll('.post-entry').forEach(row => {
    const data = postData[row.id];
    if (!data) return;

    row.addEventListener('mouseenter', () => {
      row.classList.add('active');
      infoTitle.textContent = data.title;
      infoDesc.textContent = data.desc;
      infoPanel.classList.add('has-content');
      cmd.textContent = 'open ' + data.slug;
      bar.classList.add('visible');
    });

    row.addEventListener('mouseleave', () => {
      row.classList.remove('active');
      infoTitle.textContent = 'hover an entry to inspect';
      infoDesc.textContent = '';
      infoPanel.classList.remove('has-content');
      bar.classList.remove('visible');
    });
  });
</script>

</body>
</html>
ENDINDEX

echo "Built: index.html"
echo "Done. Site is in _site/"
