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
post_data_js=""
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
  <title>${title} — Reverse Engineering Malware</title>
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

    offset=$(printf '%04X' $(( (post_idx - 1) * 32 )) )

    # Escape single quotes for JS string
    js_title=$(printf '%s' "$title" | sed "s/'/\\\\'/g")
    js_desc=$(printf '%s' "$description" | sed "s/'/\\\\'/g")

    post_data_js+="postData['post-${post_idx}']={slug:'/posts/${slug}.html',title:'${js_title}',desc:'${js_desc}',date:'${date_str}'};"

    posts_list_html+="
      <a class=\"rsrc-post-row\" id=\"post-${post_idx}\" href=\"/posts/${slug}.html\">
        <span class=\"rsrc-gutter\">.rsrc:${offset}</span>
        <span class=\"rsrc-title\">${title}</span>
      </a>"

    echo "Built: posts/${slug}.html"
done

# Generate index.html
cat > "_site/index.html" << ENDINDEX
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Reverse Engineering Malware</title>
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
      margin-bottom: 0;
      position: relative;
      display: inline-block;
    }
    .title-malware {
      font-size: 2.6rem;
      font-weight: 700;
      color: #c62828;
      text-shadow: 0 0 8px rgba(198,40,40,0.6), 0 0 20px rgba(198,40,40,0.3);
      animation: glitch-malware 6s infinite;
      letter-spacing: 0.04em;
      display: inline-block;
      margin-right: 0.15em;
    }
    .title-re {
      display: block;
      font-size: 0.95rem;
      font-family: "Fira Code", "Consolas", monospace;
      color: #50fa7b;
      opacity: 0.55;
      letter-spacing: 0.22em;
      text-transform: uppercase;
      margin-bottom: 0.2em;
    }
    .re-char { display: inline-block; }
    .re-char.scrambling { color: #50fa7b; opacity: 1; }
    @keyframes glitch-malware {
      0%,88%,100% { text-shadow: 0 0 8px rgba(198,40,40,0.6),0 0 20px rgba(198,40,40,0.3); transform: translate(0); }
      90% { text-shadow: -2px 0 #ff79c6,2px 0 #8be9fd,0 0 12px rgba(198,40,40,0.5); transform: translate(-2px,0); }
      91% { text-shadow: 3px 0 #ff79c6,-1px 0 #8be9fd; transform: translate(1px,1px); }
      92% { text-shadow: 2px 0 #ff79c6,-2px 0 #8be9fd; transform: translate(2px,0); }
      93% { text-shadow: -1px 0 #c62828,1px 0 #ff79c6; transform: translate(-1px,-1px); }
      94% { text-shadow: -1px 0 #ff79c6; transform: translate(-1px,0); }
      96% { text-shadow: 1px 0 #8be9fd; transform: translate(1px,0); }
      98% { text-shadow: 0 0 8px rgba(198,40,40,0.6),0 0 20px rgba(198,40,40,0.3); transform: translate(0); }
    }
    .magnifier {
      position: absolute;
      width: 120px;
      height: 120px;
      border-radius: 50%;
      border: 2px solid rgba(138,138,170,0.35);
      box-shadow: 0 0 12px rgba(86,37,190,0.15), inset 0 0 30px rgba(86,37,190,0.05);
      pointer-events: none;
      opacity: 0;
      transition: opacity 0.2s ease;
      z-index: 10;
      overflow: hidden;
      background: rgba(30,30,30,0.4);
    }
    .magnifier.active { opacity: 1; }
    .magnifier::after {
      content: "";
      position: absolute;
      bottom: -18px;
      right: -6px;
      width: 3px;
      height: 28px;
      background: rgba(138,138,170,0.3);
      transform: rotate(-45deg);
      border-radius: 2px;
    }
    .magnifier-content {
      position: absolute;
      white-space: nowrap;
      font-family: "Fira Code","Consolas",monospace;
      transform-origin: 0 0;
    }
    .magnifier-content .title-malware { animation: none; }

    /* Unified PE viewer container */
    .pe-viewer {
      text-align: left;
      margin: 2rem auto 0;
      max-width: 900px;
      font-family: "Fira Code", "Consolas", monospace;
      border: 1px solid #2a2a3a;
      border-radius: 6px;
      overflow: hidden;
      background: rgba(10, 10, 16, 0.7);
    }

    /* Shared toolbar (used by both .text and .rsrc) */
    .pe-section-toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.45rem 1rem;
      background: #161620;
      font-size: 0.78rem;
      color: #555;
    }
    .pe-section-toolbar .pe-section-name { color: #ff79c6; font-weight: 600; }
    .pe-section-toolbar .pe-section-flags { color: #444; font-size: 0.72rem; }

    /* Shared meta row */
    .pe-section-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.2rem 1.8rem;
      padding: 0.4rem 1rem;
      background: rgba(10, 10, 16, 0.7);
      font-size: 0.72rem;
      color: #3a3a55;
    }
    .pe-section-meta span { white-space: nowrap; }
    .pe-section-meta .meta-label { color: #3a3a55; }
    .pe-section-meta .meta-value { color: #50fa7b; }

    /* Shared body */
    .pe-section-body {
      background: rgba(10, 10, 16, 0.7);
      padding: 0.8rem 0;
    }

    /* Section divider between .text and .rsrc */
    .pe-section-divider {
      display: flex;
      align-items: center;
      gap: 0.8rem;
      padding: 0.1rem 1rem;
      background: #161620;
      border-top: 1px solid #2a2a3a;
      border-bottom: 1px solid #2a2a3a;
    }
    .pe-section-divider::before,
    .pe-section-divider::after {
      content: "";
      flex: 1;
      height: 1px;
      background: #2a2a3a;
    }
    .pe-section-divider-label {
      font-size: 0.68rem;
      color: #3a3a55;
      letter-spacing: 0.08em;
      white-space: nowrap;
    }

    /* .text disasm rows */
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
      font-size: 0.82rem;
      user-select: none;
      padding-top: 0.15em;
    }
    .pe-instr {
      color: #5625be;
      width: 3.5em;
      flex-shrink: 0;
      font-size: 0.86rem;
      user-select: none;
      padding-top: 0.15em;
    }
    .pe-asm-operand {
      color: #4a4a6a;
      font-size: 0.82rem;
      padding-top: 0.15em;
    }
    .pe-operand {
      flex: 1;
      color: #e4e4e4;
      font-family: "Segoe UI", "Roboto", sans-serif;
      font-size: 0.95rem;
      line-height: 1.65;
    }
    .pe-operand strong { color: #ff79c6; }
    .pe-operand a { color: #8be9fd !important; }
    .pe-operand a:hover { color: #50fa7b !important; }

    /* .rsrc post rows */
    .rsrc-post-row {
      display: flex;
      align-items: baseline;
      padding: 0.5rem 1rem;
      line-height: 1.7;
      cursor: pointer;
      text-decoration: none;
      border-left: 2px solid transparent;
      transition: background 0.12s ease, border-left-color 0.12s ease;
    }
    .rsrc-post-row:hover {
      background: rgba(86, 37, 190, 0.10);
      border-left-color: #5625be;
      text-decoration: none;
    }
    .rsrc-post-row .rsrc-gutter {
      width: 7em;
      flex-shrink: 0;
      color: #3a3a55;
      font-size: 0.82rem;
      user-select: none;
    }
    .rsrc-post-row:hover .rsrc-gutter { color: #5625be; }
    .rsrc-post-row .rsrc-title {
      color: #c0c0c0;
      font-family: "Segoe UI", "Roboto", sans-serif;
      font-size: 0.95rem;
      font-weight: 500;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .rsrc-post-row:hover .rsrc-title {
      color: #ff79c6;
      text-shadow: 0 0 8px rgba(255, 121, 198, 0.3);
    }

    /* Right detail panel */
    .pe-detail-panel {
      display: none;
      position: fixed;
      top: 50%;
      transform: translateY(-50%);
      right: calc((100vw - 900px) / 2 - 320px);
      width: 300px;
      font-family: "Fira Code", "Consolas", monospace;
      border: 1px solid #2a2a3a;
      border-radius: 4px;
      background: rgba(16, 16, 22, 0.95);
      overflow: hidden;
      transition: opacity 0.15s ease, border-color 0.15s ease;
      z-index: 50;
      pointer-events: none;
    }
    .pe-detail-panel.active {
      display: block;
      border-color: #3a3a55;
    }
    .pe-detail-toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.35rem 0.75rem;
      background: #161620;
      border-bottom: 1px solid #2a2a3a;
      font-size: 0.7rem;
      color: #555;
    }
    .pe-detail-toolbar .detail-label { color: #ff79c6; font-weight: 600; }
    .pe-detail-toolbar .detail-type { color: #3a3a55; }
    .pe-detail-body {
      padding: 0.75rem;
    }
    .pe-detail-title {
      color: #c0c0c0;
      font-family: "Segoe UI", "Roboto", sans-serif;
      font-size: 0.92rem;
      font-weight: 500;
      line-height: 1.5;
      margin-bottom: 0.6rem;
    }
    .pe-detail-panel.active .pe-detail-title {
      color: #ff79c6;
      text-shadow: 0 0 8px rgba(255, 121, 198, 0.2);
    }
    .pe-detail-desc {
      color: #666;
      font-family: "Segoe UI", "Roboto", sans-serif;
      font-size: 0.82rem;
      line-height: 1.55;
    }
    .pe-detail-panel.active .pe-detail-desc { color: #888; }
    .pe-detail-date {
      margin-top: 0.5rem;
      padding-top: 0.4rem;
      border-top: 1px solid #222233;
      font-size: 0.7rem;
      color: #3a3a55;
    }
    .pe-detail-date .meta-value { color: #50fa7b; }
    .pe-detail-placeholder {
      color: #2a2a3a;
      font-size: 0.75rem;
      text-align: center;
      padding: 1rem 0.5rem;
      line-height: 1.6;
    }

    /* Hide detail panel on narrow screens */
    @media (max-width: 1340px) {
      .pe-detail-panel { display: none; }
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

  </style>
</head>
<body>

<header>
  <h1 class="site-title" id="siteTitle"><span class="title-re" id="titleRE">Reverse Engineering</span><span class="title-malware">Malware</span></h1>
  <div class="magnifier" id="magnifier"></div>

  <div class="pe-viewer">
    <!-- .text section -->
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
      <div class="pe-disasm-row">
        <span class="pe-gutter">.text:0000</span>
        <span class="pe-operand">Hi! I'm Liam, a Security Researcher at <strong>CrowdStrike</strong>. This is my personal blog where I break down real-world malware samples with practical techniques &mdash; from unpacking and deobfuscation to debugging, disassembly, and memory forensics.</span>
      </div>
      <div class="pe-disasm-row">
        <span class="pe-gutter">.text:0028</span>
        <span class="pe-operand">I use tools that are freely available, most of which come pre-installed on <strong>FLARE VM</strong>, so you can follow along without extra setup.</span>
      </div>
      <div class="pe-disasm-row">
        <span class="pe-gutter">.text:0050</span>
        <span class="pe-operand">All samples referenced are publically available on <a href="https://www.virustotal.com/" target="_blank">VirusTotal</a> and <a href="https://bazaar.abuse.ch/" target="_blank">MalwareBazaar</a> and you can also grab them from my <a href="https://github.com/MZHeader/MZHeader.github.io/tree/main/samples" target="_blank">repo</a>.</span>
      </div>
    </div>

    <!-- Section divider -->
    <div class="pe-section-divider">
      <span class="pe-section-divider-label">SECTION_BOUNDARY 0x00001000</span>
    </div>

    <!-- .rsrc section -->
    <div class="pe-section-toolbar">
      <span class="pe-section-name">.rsrc</span>
      <span class="pe-section-flags">IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ</span>
    </div>
    <div class="pe-section-meta" style="display:none">
    </div>
    <div class="pe-section-body">
${posts_list_html}
    </div>
  </div>
</header>

<!-- Right detail panel -->
<div class="pe-detail-panel" id="detailPanel">
  <div class="pe-detail-toolbar">
    <span class="detail-label">RESOURCE_DATA</span>
    <span class="detail-type">RT_RCDATA</span>
  </div>
  <div class="pe-detail-body" id="detailBody">
    <div class="pe-detail-placeholder">; hover a .rsrc entry<br>; to inspect resource data</div>
  </div>
</div>

<div class="status-bar" id="statusBar">
  <span class="cmd-prompt">\$</span><span id="statusCmd"></span>
</div>

<script>
  const bar = document.getElementById('statusBar');
  const cmd = document.getElementById('statusCmd');
  const panel = document.getElementById('detailPanel');
  const detailBody = document.getElementById('detailBody');
  const placeholder = '<div class="pe-detail-placeholder">; hover a .rsrc entry<br>; to inspect resource data</div>';

  const postData = {};
  ${post_data_js}

  document.querySelectorAll('.rsrc-post-row').forEach(row => {
    row.addEventListener('mouseenter', () => {
      cmd.textContent = 'open ' + row.getAttribute('href');
      bar.classList.add('visible');

      const data = postData[row.id];
      if (data) {
        panel.classList.add('active');
        detailBody.innerHTML =
          '<div class="pe-detail-title">' + data.title + '</div>' +
          '<div class="pe-detail-desc">' + data.desc + '</div>' +
          '<div class="pe-detail-date"><span class="meta-label">TimeDateStamp:</span> <span class="meta-value">' + data.date + '</span></div>';
      }
    });
    row.addEventListener('mouseleave', () => {
      bar.classList.remove('visible');
      panel.classList.remove('active');
    });
  });

  (function() {
    const reEl = document.getElementById('titleRE');
    const reText = 'Reverse Engineering';
    const hexChars = '0123456789ABCDEF';
    reEl.innerHTML = reText.split('').map(c =>
      c === ' ' ? ' ' : '<span class="re-char" data-c="' + c + '">' + c + '</span>'
    ).join('');
    const reSpans = Array.from(reEl.querySelectorAll('.re-char'));
    function scrambleRE() {
      const pick = reSpans[Math.floor(Math.random() * reSpans.length)];
      pick.classList.add('scrambling');
      pick.textContent = hexChars[Math.floor(Math.random() * 16)];
      setTimeout(() => {
        pick.textContent = hexChars[Math.floor(Math.random() * 16)];
        setTimeout(() => {
          pick.textContent = pick.dataset.c;
          pick.classList.remove('scrambling');
        }, 60);
      }, 60);
      setTimeout(scrambleRE, 100 + Math.random() * 250);
    }
    scrambleRE();
  })();

  (function() {
    const title = document.getElementById('siteTitle');
    const mag = document.getElementById('magnifier');
    const magSize = 120;
    const zoom = 1.8;
    const clone = document.createElement('div');
    clone.className = 'magnifier-content';
    clone.innerHTML = title.innerHTML;
    mag.appendChild(clone);
    title.addEventListener('mouseenter', () => mag.classList.add('active'));
    title.addEventListener('mouseleave', () => mag.classList.remove('active'));
    title.addEventListener('mousemove', (e) => {
      const rect = title.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      mag.style.left = (e.clientX - magSize/2) + 'px';
      mag.style.top = (e.clientY - magSize/2) + 'px';
      mag.style.position = 'fixed';
      clone.style.transform = 'scale(' + zoom + ')';
      clone.style.left = (-x * zoom + magSize/2) + 'px';
      clone.style.top = (-y * zoom + magSize/2) + 'px';
    });
  })();
</script>

</body>
</html>
ENDINDEX

echo "Built: index.html"
echo "Done. Site is in _site/"
