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

    posts_list_html+="
    <li>
      <div class=\"entry-prefix\" aria-hidden=\"true\"><span class=\"prompt\">&gt;</span><span class=\"idx\">${idx}</span></div>
      <div class=\"entry-body\">
        <div class=\"entry-header\">
          <a href=\"/posts/${slug}.html\">${title}</a>
          <span class=\"post-date\">${date_str}</span>
        </div>
        $([ -n "$description" ] && echo "<p class=\"post-description\">${description}</p>")
      </div>
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

    /* Scanline overlay */
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 0, 0, 0.08) 2px,
        rgba(0, 0, 0, 0.08) 4px
      );
      pointer-events: none;
      z-index: 9999;
    }
    /* Vignette */
    body::after {
      content: "";
      position: fixed;
      inset: 0;
      background: radial-gradient(ellipse at center, transparent 40%, rgba(0, 0, 0, 0.45) 100%);
      pointer-events: none;
      z-index: 9998;
    }

    header {
      border-bottom: none;
      margin-bottom: 2.5rem;
      padding: 2rem 2rem 2rem;
      text-align: center;
      position: relative;
      background: linear-gradient(180deg, rgba(86, 37, 190, 0.06) 0%, transparent 100%);
      border-radius: 8px;
      border: 1px solid #2a2a3a;
      box-shadow:
        0 0 20px rgba(86, 37, 190, 0.08),
        inset 0 1px 0 rgba(255, 255, 255, 0.03);
    }
    header p { color: #bbbbbb; max-width: 70ch; margin: 0.5rem auto; text-align: left; }
    .normal-link { color: #8be9fd !important; }

    .ascii-art {
      font-family: monospace;
      color: #ff79c6;
      text-align: center;
      background: transparent;
      border: none;
      box-shadow: none;
      padding: 0.5rem 0;
      font-size: 0.75rem;
      line-height: 1.4;
      text-shadow: 0 0 8px #ff79c680;
      animation: pulse 4s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { text-shadow: 0 0 8px #ff79c680; }
      50% { text-shadow: 0 0 16px #ff79c6, 0 0 32px #ff79c640; }
    }

    .site-title {
      font-size: 2rem;
      font-family: "Fira Code", "Consolas", monospace;
      color: #5625be;
      text-shadow: 0 0 12px #5625be80;
      animation: glitch 6s infinite;
      margin-bottom: 0;
    }
    @keyframes glitch {
      0%, 88%, 100% {
        text-shadow: 0 0 12px #5625be80;
        transform: translate(0);
      }
      90% { text-shadow: -2px 0 #ff79c6, 2px 0 #8be9fd; transform: translate(-1px, 0); }
      92% { text-shadow: 2px 0 #ff79c6, -2px 0 #8be9fd; transform: translate(1px, 0); }
      94% { text-shadow: -1px 0 #ff79c6; transform: translate(-1px, 0); }
      96% { text-shadow: 1px 0 #8be9fd; transform: translate(1px, 0); }
      98% { text-shadow: 0 0 12px #5625be80; transform: translate(0); }
    }

    .hex-dump {
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.72rem;
      color: #444;
      text-align: center;
      margin: 0.75rem auto;
      letter-spacing: 0.05em;
      background: rgba(0, 0, 0, 0.25);
      display: inline-block;
      padding: 0.4rem 1rem;
      border-radius: 4px;
      border: 1px solid #2a2a3a;
    }
    .hex-dump .hex-addr { color: #333; margin-right: 1em; }
    .hex-dump .hex-bytes { color: #4a4a6a; margin-right: 1em; }
    .hex-dump .hex-mz { color: #5625be90; }

    .intro-block { text-align: left; margin-top: 1.5rem; }

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
      left: 0;
      right: 0;
      padding: 0.3rem 1rem;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.75rem;
      color: #50fa7b;
      background: rgba(18, 18, 24, 0.95);
      border-top: 1px solid #2a2a3a;
      opacity: 0;
      transition: opacity 0.15s ease;
      pointer-events: none;
      z-index: 100;
    }
    .status-bar.visible { opacity: 1; }
    .status-bar .cmd-prompt { color: #5625be; margin-right: 0.5em; }

    ul { list-style: none; padding: 0; margin: 0; font-family: "Fira Code", "Consolas", monospace; }
    li {
      display: flex;
      align-items: flex-start;
      gap: 0;
      margin-bottom: 0;
      padding: 0.7rem 0.9rem;
      background: transparent;
      border-left: 2px solid transparent;
      border-bottom: 1px solid #2a2a3a;
      position: relative;
      transition: background 0.15s ease, border-color 0.15s ease;
    }
    li::before {
      content: "";
      position: absolute;
      inset: 0;
      background: repeating-linear-gradient(0deg, transparent, transparent 1px, rgba(255,255,255,0.008) 1px, rgba(255,255,255,0.008) 2px);
      pointer-events: none;
      opacity: 0;
      transition: opacity 0.2s ease;
    }
    li:hover { background: rgba(86, 37, 190, 0.07); border-left-color: #5625be; }
    li:hover::before { opacity: 1; }
    .entry-prefix {
      flex-shrink: 0;
      width: 3.8rem;
      padding-top: 0.15rem;
      user-select: none;
      display: flex;
      align-items: baseline;
      gap: 0.3rem;
    }
    .entry-prefix .prompt { color: #5625be; font-weight: 700; font-size: 0.8rem; transition: color 0.15s ease; }
    li:hover .entry-prefix .prompt { color: #50fa7b; }
    .entry-prefix .idx { color: #444; font-size: 0.72rem; letter-spacing: 0.05em; }
    li:hover .entry-prefix .idx { color: #666; }
    .entry-body { flex: 1; min-width: 0; }
    .entry-header { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; }
    .entry-header a { font-size: 0.95rem; font-weight: 600; color: #dcdcdc; text-decoration: none; transition: color 0.15s ease; }
    li:hover .entry-header a { color: #8be9fd; }
    li:hover .entry-header a:hover { color: #ff79c6; }
    .post-date { flex-shrink: 0; color: #555; font-size: 0.75rem; letter-spacing: 0.04em; white-space: nowrap; }
    li:hover .post-date { color: #50fa7b; }
    .post-description { color: #777; margin: 0.2rem 0 0 0; font-size: 0.8rem; line-height: 1.55; font-family: "Segoe UI", "Roboto", sans-serif; }
    li:hover .post-description { color: #999; }
  </style>
</head>
<body>

<header>
  <h1 class="site-title">Malware Under the Microscope</h1>
  <pre class="ascii-art">
 __  __ ______
|  \/  |___  /
| |\/| |  / /
| |  | | / /__
|_|  |_|/____|
 MZ HEADER
</pre>
  <div class="hex-dump">
    <span class="hex-addr">00000000</span>
    <span class="hex-bytes">4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00</span>
    <span class="hex-mz">MZ..............</span>
  </div>

  <div class="intro-block">
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
  </div>
</header>

<h2 class="section-heading"><span class="prompt">\$</span> ls ./write-ups/</h2>
<ul>
${posts_list_html}
</ul>

<div class="status-bar" id="statusBar">
  <span class="cmd-prompt">\$</span><span id="statusCmd"></span>
</div>

<script>
  const bar = document.getElementById('statusBar');
  const cmd = document.getElementById('statusCmd');
  document.querySelectorAll('li').forEach(li => {
    const slug = li.querySelector('a').getAttribute('href').replace('/posts/', '').replace('.html', '');
    li.addEventListener('mouseenter', () => {
      cmd.textContent = 'cd ./write-ups/' + slug;
      bar.classList.add('visible');
    });
    li.addEventListener('mouseleave', () => {
      bar.classList.remove('visible');
    });
  });
</script>

</body>
</html>
ENDINDEX

echo "Built: index.html"
echo "Done. Site is in _site/"
