#!/bin/bash
set -e

mkdir -p _site/posts _site/css

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
    img { max-width: 100%; height: auto; border-radius: 4px; }
    .back-link {
      display: inline-block;
      margin-bottom: 2rem;
      color: #8be9fd;
      font-size: 0.9rem;
    }
    .post-meta { color: #888; font-size: 0.85rem; margin-bottom: 2rem; }
'

# Write shared CSS to external file
printf '%s\n' "$SHARED_CSS" > _site/css/main.css

GA_HEAD='
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-48M02RY99Q"></script>
  <script>
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag("js", new Date());
    gtag("config", "G-48M02RY99Q");
  </script>
'

ASSET_HEAD='
  <link rel="stylesheet" href="/css/main.css" />
  <link rel="icon" href="/favicon.ico" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&display=swap" rel="stylesheet" />
'

HLJS_HEAD='
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/base16/dracula.min.css">
  <script defer src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js" onload="hljs.highlightAll()"></script>
'

posts_list_html=""
post_data_js=""
post_idx=0

declare -a p_slugs p_titles p_dates p_date_strs p_descs p_tags p_badge_classes

# ── Pass 1: collect metadata, run pandoc, build list HTML ──────────────────
for post in $(ls _posts/*.md | sort -r); do
    post_idx=$((post_idx + 1))
    filename=$(basename "$post" .md)
    date_str="${filename:0:10}"
    slug="${filename:11}"

    formatted_date=$(date -d "$date_str" "+%b %-d, %Y" 2>/dev/null || date -j -f "%Y-%m-%d" "$date_str" "+%b %-d, %Y")
    epoch=$(date -d "$date_str" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "$date_str" +%s)
    hex_ts=$(printf '0x%08X' "$epoch")
    short_date=$(date -d "$date_str" "+%-d %b %Y" 2>/dev/null || date -j -f "%Y-%m-%d" "$date_str" "+%-d %b %Y")
    description=$(awk 'BEGIN{f=0} /^---/{f++; next} f==1 && /^description:/{sub(/^description: */, ""); gsub(/^"|"$/, ""); print; exit}' "$post")
    tags=$(awk 'BEGIN{f=0} /^---/{f++; next} f==1 && /^tags:/{sub(/^tags: */, ""); gsub(/^"|"$/, ""); print; exit}' "$post")
    [ -z "$tags" ] && tags="Analysis"
    title=$(grep "^## " "$post" | head -1 | sed 's/^## //')
    [ -z "$title" ] && title="$slug"

    case "$tags" in
      RAT)         badge_class="rsrc-badge--rats" ;;
      InfoStealer) badge_class="rsrc-badge--infostealer" ;;
      CTF)         badge_class="rsrc-badge--ctf" ;;
      Loader)      badge_class="rsrc-badge--loader" ;;
      Downloader)  badge_class="rsrc-badge--downloader" ;;
      Trojan)      badge_class="rsrc-badge--trojan" ;;
      *)           badge_class="rsrc-badge--analysis" ;;
    esac

    p_slugs[$post_idx]="$slug"
    p_titles[$post_idx]="$title"
    p_dates[$post_idx]="$formatted_date"
    p_date_strs[$post_idx]="$date_str"
    p_descs[$post_idx]="$description"
    p_tags[$post_idx]="$tags"
    p_badge_classes[$post_idx]="$badge_class"

    pandoc "$post" \
        --from markdown+yaml_metadata_block-implicit_figures \
        --to html \
        --no-highlight > "/tmp/mzbuild_${slug}.html"

    offset=$(printf '%04X' $(( (post_idx - 1) * 32 )) )

    js_title=$(printf '%s' "$title" | sed "s/'/\\\\'/g")
    js_desc=$(printf '%s' "$description" | sed "s/'/\\\\'/g")

    post_data_js+="postData['post-${post_idx}']={slug:'/posts/${slug}.html',title:'${js_title}',desc:'${js_desc}',date:'${date_str}'};"

    posts_list_html+="
      <a class=\"rsrc-post-row\" id=\"post-${post_idx}\" href=\"/posts/${slug}.html\">
        <span class=\"rsrc-gutter\">.rsrc:${offset}</span>
        <span class=\"rsrc-title-block\">
          <span class=\"rsrc-title\">${title}</span>
          <span class=\"rsrc-meta\">; TimeDateStamp: ${hex_ts} (${short_date}) &nbsp;&middot;&nbsp; <span class=\"rsrc-badge ${badge_class}\">${tags}</span></span>
        </span>
      </a>"
done

total_posts=$post_idx

# ── Pass 2: write each post HTML with full sidebar ─────────────────────────
for i in $(seq 1 $total_posts); do
    slug="${p_slugs[$i]}"
    title="${p_titles[$i]}"
    formatted_date="${p_dates[$i]}"
    date_str="${p_date_strs[$i]}"
    description="${p_descs[$i]}"
    short_title="${title%%:*}"

    # Prev = newer post (lower index), Next = older post (higher index)
    prev_html=""
    next_html=""
    prev_i=$((i - 1))
    next_i=$((i + 1))
    if [ $prev_i -ge 1 ]; then
        prev_label="${p_titles[$prev_i]%%:*}"
        prev_html="<a class=\"post-pagination-link\" href=\"/posts/${p_slugs[$prev_i]}.html\">&larr; ${prev_label}</a>"
    fi
    if [ $next_i -le $total_posts ]; then
        next_label="${p_titles[$next_i]%%:*}"
        next_html="<a class=\"post-pagination-link post-pagination-link--right\" href=\"/posts/${p_slugs[$next_i]}.html\">${next_label} &rarr;</a>"
    fi

    cat > "_site/posts/${slug}.html" << ENDHEADER
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title} — MZHeader: Reverse Engineering Malware</title>
  <meta name="description" content="${description}" />
  <meta name="author" content="Liam Chugg" />
  <link rel="canonical" href="https://mzheader.tech/posts/${slug}.html" />
  <meta property="og:type" content="article" />
  <meta property="og:title" content="${title}" />
  <meta property="og:description" content="${description}" />
  <meta property="og:url" content="https://mzheader.tech/posts/${slug}.html" />
  <meta property="og:site_name" content="Reverse Engineering Malware" />
  <meta property="article:published_time" content="${date_str}" />
  <meta property="article:author" content="Liam Chugg" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="${title}" />
  <meta name="twitter:description" content="${description}" />
  ${ASSET_HEAD}
  ${GA_HEAD}
  ${HLJS_HEAD}
  <style>
    /* Override body for sidebar layout */
    body {
      max-width: none;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: row;
      min-height: 100vh;
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

    /* ── Sidebar ── */
    #rsrc-sidebar {
      width: 230px;
      min-width: 230px;
      position: fixed;
      top: 0;
      left: 0;
      bottom: 0;
      overflow-y: auto;
      overflow-x: hidden;
      background: #13131a;
      border-right: 1px solid #2a2a3a;
      display: flex;
      flex-direction: column;
      z-index: 100;
      font-family: "Fira Code", "Consolas", monospace;
    }
    #rsrc-sidebar::-webkit-scrollbar { width: 4px; }
    #rsrc-sidebar::-webkit-scrollbar-track { background: #13131a; }
    #rsrc-sidebar::-webkit-scrollbar-thumb { background: #2a2a3a; border-radius: 2px; }

    .rsrc-toolbar {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.55rem 0.75rem;
      background: #1a1a22;
      border-bottom: 1px solid #2a2a3a;
      position: sticky;
      top: 0;
      z-index: 101;
    }
    .rsrc-toolbar-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #5625be;
      box-shadow: 0 0 4px #5625be88;
      flex-shrink: 0;
    }
    .rsrc-toolbar-label {
      font-size: 0.7rem;
      color: #8be9fd;
      letter-spacing: 0.08em;
      flex: 1;
    }
    .rsrc-toolbar-count {
      font-size: 0.65rem;
      color: #3a3a55;
    }
    .rsrc-section-header {
      font-size: 0.62rem;
      color: #3a3a55;
      letter-spacing: 0.1em;
      padding: 0.5rem 0.75rem 0.3rem;
      border-bottom: 1px solid #1e1e28;
    }
    .rsrc-post-list { flex: 1; }

    /* Sidebar post rows — reuse rsrc-post-row but override widths */
    #rsrc-sidebar a.rsrc-post-row {
      display: block;
      padding: 0.45rem 0.75rem;
      border-left: 2px solid transparent;
      border-bottom: 1px solid #1a1a22;
      text-decoration: none;
      transition: background 0.1s, border-color 0.1s;
    }
    #rsrc-sidebar a.rsrc-post-row:hover {
      background: rgba(86, 37, 190, 0.1);
      border-left-color: #5625be;
    }
    #rsrc-sidebar a.rsrc-post-row.active {
      background: rgba(139, 233, 253, 0.05);
      border-left-color: #8be9fd;
    }
    #rsrc-sidebar .rsrc-gutter {
      display: block;
      font-size: 0.6rem;
      color: #3a3a55;
      margin-bottom: 0.1rem;
      width: auto;
    }
    #rsrc-sidebar a.rsrc-post-row.active .rsrc-gutter { color: #5625be; }
    #rsrc-sidebar .rsrc-title {
      display: block;
      font-family: "Segoe UI", "Roboto", sans-serif;
      font-size: 0.75rem;
      font-weight: 500;
      color: #888;
      white-space: normal;
      overflow: visible;
      text-overflow: unset;
      line-height: 1.35;
    }
    #rsrc-sidebar a.rsrc-post-row:hover .rsrc-title { color: #c0c0c0; }
    #rsrc-sidebar a.rsrc-post-row.active .rsrc-title { color: #8be9fd; }
    #rsrc-sidebar .rsrc-meta { display: none; }

    /* ── Main content ── */
    #post-main {
      margin-left: 230px;
      flex: 1;
      min-width: 0;
      padding: 2rem 4rem;
    }
    .post-nav, article, .post-pagination {
      max-width: 800px;
      margin-left: auto;
      margin-right: auto;
    }

    /* ── Top nav ── */
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
      text-decoration: none;
    }
    .back-link:hover { text-shadow: 0 0 10px rgba(80, 250, 123, 0.6); }
    .post-meta {
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.78rem;
      color: #555;
      letter-spacing: 0.03em;
    }

    /* ── Article ── */
    article h2:first-of-type {
      font-size: 1.9rem;
      color: #7c4dff;
      text-shadow: 0 0 16px rgba(124, 77, 255, 0.5), 0 0 32px rgba(124, 77, 255, 0.2);
      border-bottom: 1px solid #2a2a3a;
      padding-bottom: 0.5rem;
      margin-bottom: 1.5rem;
    }
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
    article p { color: #b8b8c8; line-height: 1.75; }
    article li { color: #b8b8c8; line-height: 1.75; }
    article strong { color: #dcdcdc; }

    article table {
      width: 100%;
      border-collapse: collapse;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.85rem;
      margin: 1.5rem 0;
      border: 1px solid #2a2a3a;
      border-radius: 4px;
      overflow: hidden;
    }
    article th {
      background: #1a1a22;
      color: #8be9fd;
      text-align: left;
      padding: 0.5rem 0.75rem;
      border-bottom: 2px solid #5625be;
      font-weight: 600;
      letter-spacing: 0.03em;
      white-space: nowrap;
    }
    article td {
      padding: 0.45rem 0.75rem;
      border-bottom: 1px solid #1e1e28;
      color: #c8c8d8;
      vertical-align: top;
    }
    article tr:last-child td { border-bottom: none; }
    article tr:hover td { background: rgba(86, 37, 190, 0.07); }

    /* ── Sidebar toggle ── */
    #rsrc-sidebar {
      transition: width 0.22s cubic-bezier(0.4, 0, 0.2, 1),
                  min-width 0.22s cubic-bezier(0.4, 0, 0.2, 1);
    }
    #rsrc-sidebar.collapsed {
      width: 32px;
      min-width: 32px;
    }
    #rsrc-sidebar.collapsed .rsrc-section-header,
    #rsrc-sidebar.collapsed .rsrc-post-list,
    #rsrc-sidebar.collapsed .rsrc-toolbar-label,
    #rsrc-sidebar.collapsed .rsrc-toolbar-count,
    #rsrc-sidebar.collapsed .rsrc-toolbar-dot {
      display: none;
    }
    #rsrc-sidebar.collapsed .rsrc-toolbar {
      padding: 0;
      justify-content: center;
    }
    #post-main {
      transition: margin-left 0.22s cubic-bezier(0.4, 0, 0.2, 1);
    }
    body.sidebar-collapsed #post-main {
      margin-left: 32px;
    }
    .rsrc-toggle-btn {
      background: none;
      border: none;
      cursor: pointer;
      color: #3a3a55;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.75rem;
      line-height: 1;
      padding: 0.2rem 0.25rem;
      margin-left: auto;
      flex-shrink: 0;
      transition: color 0.15s;
      user-select: none;
    }
    .rsrc-toggle-btn:hover { color: #8be9fd; }
    #rsrc-sidebar.collapsed .rsrc-toggle-btn {
      margin-left: 0;
      color: #5625be;
      padding: 0.55rem 0;
      width: 32px;
      text-align: center;
    }
    #rsrc-sidebar.collapsed .rsrc-toggle-btn:hover { color: #8be9fd; }


    /* ── Mobile nav bar ── */
    #mobile-nav { display: none; }

    /* ── Mobile ── */
    @media (max-width: 900px) {
      body { display: block; overflow-x: hidden; }
      #rsrc-sidebar { display: none; }
      #post-main { margin-left: 0; max-width: 100%; padding: 3.5rem 1rem 1rem; }
      .post-nav { padding-bottom: 0.5rem; margin-bottom: 1.5rem; }
      .post-nav .back-link { display: none; }
      article h2:first-of-type { font-size: 1.4rem; }
      article h2 { font-size: 1.05rem; }
      pre code { font-size: 0.8rem; }
      body.sidebar-collapsed #post-main { margin-left: 0; }
      #mobile-nav {
        display: flex;
        position: fixed;
        top: 0; left: 0; right: 0;
        height: 44px;
        background: #13131a;
        border-bottom: 1px solid #2a2a3a;
        align-items: center;
        padding: 0 1rem;
        gap: 0.75rem;
        z-index: 200;
        font-family: "Fira Code", "Consolas", monospace;
      }
      #mobile-nav .mob-back {
        color: #50fa7b;
        text-decoration: none;
        font-size: 0.82rem;
        white-space: nowrap;
      }
      #mobile-nav .mob-back:hover { color: #8be9fd; }
      #mobile-nav .mob-sep { color: #2a2a3a; font-size: 0.8rem; }
      #mobile-nav .mob-title {
        color: #555570;
        font-size: 0.75rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        flex: 1;
        min-width: 0;
      }
    }

    /* ── Post pagination ── */
    .post-pagination {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 1px solid #2a2a3a;
      gap: 1rem;
    }
    .post-pagination-link {
      color: #8be9fd;
      text-decoration: none;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.82rem;
    }
    .post-pagination-link--right { margin-left: auto; text-align: right; }
    .post-pagination-link:hover { color: #50fa7b; }

    /* ── Copy button on code blocks ── */
    .pre-wrapper { position: relative; }
    .copy-btn {
      position: absolute;
      top: 0.4rem;
      right: 0.4rem;
      background: #2a2a3a;
      border: 1px solid #444;
      color: #8be9fd;
      font-family: "Fira Code", monospace;
      font-size: 0.7rem;
      padding: 0.15rem 0.4rem;
      border-radius: 3px;
      cursor: pointer;
      opacity: 0;
      transition: opacity 0.15s;
    }
    .pre-wrapper:hover .copy-btn { opacity: 1; }
    .copy-btn.copied { color: #50fa7b; border-color: #50fa7b; }
  </style>
</head>
<body>

  <nav id="rsrc-sidebar">
    <div class="rsrc-toolbar">
      <span class="rsrc-toolbar-dot"></span>
      <span class="rsrc-toolbar-label">.rsrc</span>
      <span class="rsrc-toolbar-count" id="rsrc-count"></span>
      <button class="rsrc-toggle-btn" id="rsrc-toggle" title="Toggle sidebar" aria-label="Toggle sidebar">&#xBB;</button>
    </div>
    <div class="rsrc-section-header">POSTS</div>
    <div class="rsrc-post-list">
${posts_list_html}
    </div>
  </nav>

  <div id="mobile-nav">
    <a class="mob-back" href="/">&larr; cd ..</a>
    <span class="mob-sep">/</span>
    <span class="mob-title">${short_title}</span>
  </div>

  <div id="post-main">
    <div class="post-nav">
      <a class="back-link" href="/">&larr; cd ..</a>
      <span class="post-meta">${formatted_date}</span>
    </div>
    <article>
ENDHEADER

    cat "/tmp/mzbuild_${slug}.html" >> "_site/posts/${slug}.html"

    cat >> "_site/posts/${slug}.html" << ENDFOOTER
    </article>
    <nav class="post-pagination">
      ${prev_html}
      ${next_html}
    </nav>
  </div>

<script>
(function() {
  var currentSlug = "${slug}";
  var rows = document.querySelectorAll("#rsrc-sidebar a.rsrc-post-row");
  var activeRow = null;
  rows.forEach(function(row) {
    if (row.getAttribute("href") && row.getAttribute("href").indexOf("/" + currentSlug + ".html") !== -1) {
      row.classList.add("active");
      activeRow = row;
    }
  });
  var countEl = document.getElementById("rsrc-count");
  if (countEl) countEl.textContent = rows.length + " entries";
  if (activeRow) setTimeout(function() { activeRow.scrollIntoView({ block: "center", behavior: "instant" }); }, 0);

  // ── Sidebar toggle ──
  var sidebar = document.getElementById("rsrc-sidebar");
  var toggleBtn = document.getElementById("rsrc-toggle");

  function applyCollapsed(collapsed) {
    if (collapsed) {
      sidebar.classList.add("collapsed");
      document.body.classList.add("sidebar-collapsed");
      toggleBtn.innerHTML = "&#xBB;";
      toggleBtn.title = "Expand sidebar";
    } else {
      sidebar.classList.remove("collapsed");
      document.body.classList.remove("sidebar-collapsed");
      toggleBtn.innerHTML = "&#xAB;";
      toggleBtn.title = "Collapse sidebar";
    }
  }

  var savedState = localStorage.getItem("rsrc-sidebar-collapsed");
  applyCollapsed(savedState === "1");

  if (toggleBtn) {
    toggleBtn.addEventListener("click", function() {
      var isCollapsed = sidebar.classList.contains("collapsed");
      var next = !isCollapsed;
      localStorage.setItem("rsrc-sidebar-collapsed", next ? "1" : "0");
      applyCollapsed(next);
    });
  }

  // ── Copy buttons on code blocks ──
  document.querySelectorAll("pre").forEach(function(pre) {
    var wrapper = document.createElement("div");
    wrapper.className = "pre-wrapper";
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);
    var btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.textContent = "copy";
    btn.addEventListener("click", function() {
      var code = pre.querySelector("code");
      navigator.clipboard.writeText(code ? code.innerText : pre.innerText).then(function() {
        btn.textContent = "copied!";
        btn.classList.add("copied");
        setTimeout(function() { btn.textContent = "copy"; btn.classList.remove("copied"); }, 1500);
      });
    });
    wrapper.appendChild(btn);
  });
})();
</script>

</body>
</html>
ENDFOOTER

    echo "Built: posts/${slug}.html"
done

# Generate index.html
cat > "_site/index.html" << ENDINDEX
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MZHeader: Reverse Engineering Malware</title>
  <meta name="description" content="Malware analysis blog by Liam Chugg, Security Researcher at CrowdStrike. Practical reverse engineering: unpacking, deobfuscation, debugging, disassembly, and memory forensics." />
  <meta name="author" content="Liam Chugg" />
  <link rel="canonical" href="https://mzheader.tech/" />
  <meta property="og:type" content="website" />
  <meta property="og:title" content="Reverse Engineering Malware" />
  <meta property="og:description" content="Malware analysis blog by Liam Chugg, Security Researcher at CrowdStrike. Practical reverse engineering: unpacking, deobfuscation, debugging, disassembly, and memory forensics." />
  <meta property="og:url" content="https://mzheader.tech/" />
  <meta property="og:site_name" content="Reverse Engineering Malware" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="Reverse Engineering Malware" />
  <meta name="twitter:description" content="Malware analysis blog by Liam Chugg, Security Researcher at CrowdStrike. Practical reverse engineering: unpacking, deobfuscation, debugging, disassembly, and memory forensics." />
  ${ASSET_HEAD}
  ${GA_HEAD}
  ${HLJS_HEAD}
  <style>
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
      margin-bottom: 0.8rem;
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
      90% { text-shadow: -2px 0 #8be9fd,2px 0 #8be9fd,0 0 12px rgba(198,40,40,0.5); transform: translate(-2px,0); }
      91% { text-shadow: 3px 0 #8be9fd,-1px 0 #8be9fd; transform: translate(1px,1px); }
      92% { text-shadow: 2px 0 #8be9fd,-2px 0 #8be9fd; transform: translate(2px,0); }
      93% { text-shadow: -1px 0 #c62828,1px 0 #8be9fd; transform: translate(-1px,-1px); }
      94% { text-shadow: -1px 0 #8be9fd; transform: translate(-1px,0); }
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

    /* PE window wrapper — unified container for titlebar + viewer */
    .pe-window {
      max-width: 900px;
      margin: 0 auto;
      border: 1px solid #2a2a3a;
      border-radius: 6px;
      overflow: hidden;
      background: rgba(10, 10, 16, 0.7);
    }

    /* Window titlebar */
    .pe-window-titlebar {
      display: flex;
      align-items: center;
      padding: 0.4rem 0.75rem;
      background: #12121a;
      border-bottom: 1px solid #2a2a3a;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.72rem;
      color: #555;
      gap: 0.6rem;
      user-select: none;
    }
    .pe-window-dots {
      display: flex;
      gap: 5px;
      margin-right: 0.3rem;
      flex-shrink: 0;
    }
    .pe-window-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
    }
    .pe-window-dot.dot-close { background: #c62828; box-shadow: 0 0 4px rgba(198,40,40,0.5); }
    .pe-window-dot.dot-min { background: #555; }
    .pe-window-dot.dot-max { background: #555; }
    .pe-window-titlebar .window-title {
      color: #888;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .pe-window-titlebar .window-title .wt-app { color: #5625be; }
    .pe-window-titlebar .window-title .wt-sep { color: #333; margin: 0 0.3em; }
    .pe-window-titlebar .window-title .wt-file { color: #c62828; }
    .pe-window-titlebar .window-title .wt-path { color: #555; }
    .pe-window-titlebar .window-spacer { flex: 1; }
    .pe-window-titlebar .window-tag {
      color: #50fa7b;
      opacity: 0.55;
      font-size: 0.65rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      white-space: nowrap;
    }

    /* Unified PE viewer container */
    .pe-viewer {
      text-align: left;
      font-family: "Fira Code", "Consolas", monospace;
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
    .pe-section-toolbar .pe-section-name { color: #8be9fd; font-weight: 600; }
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

    /* Section divider — PE section table entry */
    .pe-section-divider {
      padding: 0.3rem 1rem;
      background: rgba(13, 13, 20, 0.85);
      border-top: 1px solid #1e1e28;
      border-bottom: 1px solid #1e1e28;
      white-space: nowrap;
      overflow: hidden;
    }
    .pe-section-divider-label {
      font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
      font-size: 0.72rem;
      color: #2e2e4a;
      letter-spacing: 0.04em;
    }
    .pe-section-divider-label .pe-divider-detail {
      color: #2e2e4a;
    }
    @media (max-width: 600px) {
      .pe-section-divider-label .pe-divider-detail {
        display: none;
      }
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
    .pe-operand strong { color: #8be9fd; }
    .pe-operand a { color: #8be9fd !important; }
    .pe-operand a:hover { color: #50fa7b !important; }
    .pe-comment {
      flex: 1;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.88rem;
      color: #6272a4;
      line-height: 1.65;
    }
    .pe-comment strong { color: #c62828; font-weight: 600; }
    .pe-comment a { color: #8be9fd !important; }
    .pe-comment a:hover { color: #50fa7b !important; }

    /* .rsrc post rows */
    .rsrc-post-row {
      display: flex;
      align-items: flex-start;
      padding: 0.55rem 1rem;
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
      padding-top: 0.15rem;
    }
    .rsrc-post-row:hover .rsrc-gutter { color: #5625be; }
    .rsrc-title-block {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }
    .rsrc-post-row .rsrc-title {
      color: #e8e8e8;
      font-family: "Segoe UI", "Roboto", sans-serif;
      font-size: 0.95rem;
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      line-height: 1.5;
    }
    .rsrc-post-row:hover .rsrc-title {
      color: #8be9fd;
      text-shadow: 0 0 8px rgba(139, 233, 253, 0.3);
    }
    .rsrc-meta {
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.74rem;
      color: #555570;
      letter-spacing: 0.01em;
      line-height: 1.4;
    }
    .rsrc-post-row:hover .rsrc-meta { color: #6e6e90; }
    .rsrc-badge {
      display: inline-block;
      font-size: 0.62rem;
      font-weight: 400;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      opacity: 0.65;
    }
    .rsrc-badge::before {
      content: '\25CF\00A0';
      font-size: 0.5em;
      vertical-align: middle;
      opacity: 0.9;
    }
    .rsrc-badge--trojan      { color: #e07070; }
    .rsrc-badge--trojan::before      { color: #c62828; }
    .rsrc-badge--infostealer { color: #8be9fd; }
    .rsrc-badge--infostealer::before { color: #8be9fd; }
    .rsrc-badge--downloader  { color: #50fa7b; }
    .rsrc-badge--downloader::before  { color: #50fa7b; }
    .rsrc-badge--loader      { color: #50fa7b; }
    .rsrc-badge--loader::before      { color: #50fa7b; }
    .rsrc-badge--rats        { color: #bd93f9; }
    .rsrc-badge--rats::before        { color: #bd93f9; }
    .rsrc-badge--ctf         { color: #ffb86c; }
    .rsrc-badge--ctf::before         { color: #ffb86c; }
    .rsrc-badge--analysis    { color: #8a8aaa; }
    .rsrc-badge--analysis::before    { color: #8a8aaa; }

    /* Right detail panel */
    .pe-detail-panel {
      display: none;
      position: fixed;
      top: 50%;
      transform: translateY(-50%);
      right: 1.5rem;
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
    .pe-detail-toolbar .detail-label { color: #8be9fd; font-weight: 600; }
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
      color: #8be9fd;
      text-shadow: 0 0 8px rgba(139, 233, 253, 0.2);
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

    /* Hide detail panel on touch/non-hover devices — overrides .active { display: block } */
    @media (hover: none) {
      .pe-detail-panel { display: none !important; }
    }

    /* ── Category filter bar ── */
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.35rem;
      padding: 0.5rem 1rem 0.45rem;
      border-bottom: 1px solid #1e1e28;
      font-family: "Fira Code", "Consolas", monospace;
    }
    .filter-bar-label {
      font-size: 0.65rem;
      color: #3a3a55;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-right: 0.3rem;
      user-select: none;
    }
    .filter-btn {
      background: transparent;
      border: 1px solid #2a2a3a;
      color: #555570;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.62rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      padding: 0.2rem 0.55rem;
      border-radius: 2px;
      cursor: pointer;
      transition: background 0.12s, color 0.12s, border-color 0.12s, box-shadow 0.12s;
      user-select: none;
    }
    .filter-btn:hover {
      border-color: #5625be;
      color: #8a8aaa;
    }
    .filter-btn.active {
      background: rgba(86, 37, 190, 0.15);
      border-color: #5625be;
      color: #8be9fd;
      box-shadow: 0 0 6px rgba(86, 37, 190, 0.3);
    }
    .filter-btn[data-cat="all"].active { color: #8be9fd; border-color: #5625be; }
    .filter-btn[data-cat="trojan"] { border-color: rgba(198,40,40,0.3); }
    .filter-btn[data-cat="trojan"]:hover { border-color: #c62828; color: #e07070; }
    .filter-btn[data-cat="trojan"].active { background: rgba(198,40,40,0.12); border-color: #c62828; color: #e07070; box-shadow: 0 0 6px rgba(198,40,40,0.25); }
    .filter-btn[data-cat="infostealer"] { border-color: rgba(139,233,253,0.2); }
    .filter-btn[data-cat="infostealer"]:hover { border-color: #8be9fd; color: #8be9fd; }
    .filter-btn[data-cat="infostealer"].active { background: rgba(139,233,253,0.08); border-color: #8be9fd; color: #8be9fd; box-shadow: 0 0 6px rgba(139,233,253,0.2); }
    .filter-btn[data-cat="downloader"] { border-color: rgba(80,250,123,0.2); }
    .filter-btn[data-cat="downloader"]:hover { border-color: #50fa7b; color: #50fa7b; }
    .filter-btn[data-cat="downloader"].active { background: rgba(80,250,123,0.08); border-color: #50fa7b; color: #50fa7b; box-shadow: 0 0 6px rgba(80,250,123,0.2); }
    .filter-btn[data-cat="loader"] { border-color: rgba(80,250,123,0.2); }
    .filter-btn[data-cat="loader"]:hover { border-color: #50fa7b; color: #50fa7b; }
    .filter-btn[data-cat="loader"].active { background: rgba(80,250,123,0.08); border-color: #50fa7b; color: #50fa7b; box-shadow: 0 0 6px rgba(80,250,123,0.2); }
    .filter-btn[data-cat="rats"] { border-color: rgba(189,147,249,0.2); }
    .filter-btn[data-cat="rats"]:hover { border-color: #bd93f9; color: #bd93f9; }
    .filter-btn[data-cat="rats"].active { background: rgba(189,147,249,0.08); border-color: #bd93f9; color: #bd93f9; box-shadow: 0 0 6px rgba(189,147,249,0.2); }
    .filter-btn[data-cat="ctf"] { border-color: rgba(255,184,108,0.2); }
    .filter-btn[data-cat="ctf"]:hover { border-color: #ffb86c; color: #ffb86c; }
    .filter-btn[data-cat="ctf"].active { background: rgba(255,184,108,0.08); border-color: #ffb86c; color: #ffb86c; box-shadow: 0 0 6px rgba(255,184,108,0.2); }
    .filter-btn[data-cat="analysis"] { border-color: rgba(138,138,170,0.2); }
    .filter-btn[data-cat="analysis"]:hover { border-color: #8a8aaa; color: #8a8aaa; }
    .filter-btn[data-cat="analysis"].active { background: rgba(138,138,170,0.08); border-color: #8a8aaa; color: #8a8aaa; box-shadow: 0 0 6px rgba(138,138,170,0.2); }
    .filter-count {
      font-size: 0.55rem;
      color: #3a3a55;
      margin-left: 0.15rem;
    }
    .filter-btn.active .filter-count { color: inherit; opacity: 0.7; }

    @media (max-width: 600px) {
      body { padding: 1rem; }
      .title-malware { font-size: 1.8rem; }
      .title-re { font-size: 0.75rem; letter-spacing: 0.12em; }
      .pe-section-flags { display: none; }
      .pe-gutter { display: none; }
      .rsrc-post-row .rsrc-gutter { display: none; }
      .rsrc-post-row .rsrc-title { white-space: normal; }
      .pe-window-titlebar .wt-path { display: none; }
      .pe-window-titlebar .window-tag { display: none; }
    }

  </style>
</head>
<body>

<header>
  <h1 class="site-title" id="siteTitle"><span class="title-re" id="titleRE">Reverse Engineering</span><span class="title-malware">Malware</span></h1>
  <div class="magnifier" id="magnifier"></div>

  <div class="pe-window">
    <div class="pe-window-titlebar">
      <div class="pe-window-dots">
        <span class="pe-window-dot dot-close"></span>
        <span class="pe-window-dot dot-min"></span>
        <span class="pe-window-dot dot-max"></span>
      </div>
      <span class="window-title"><span class="wt-app">pe-viewer</span><span class="wt-sep">&#8212;</span><span class="wt-path">C:\Samples\</span><span class="wt-file">unknown.exe</span></span>
      <span class="window-spacer"></span>
      <span class="window-tag">reverse engineering / malware</span>
    </div>
  <div class="pe-viewer">
    <!-- .text section -->
    <div class="pe-section-toolbar">
      <span class="pe-section-name">.text</span>
      <span class="pe-section-flags" title="IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ">Characteristics: 0x60000020</span>
    </div>
    <div class="pe-section-meta" style="display:none"></div>
    <div class="pe-section-body">
      <div class="pe-disasm-row">
        <span class="pe-gutter">.text:0000</span>
        <span class="pe-comment">; <strong>Liam Chugg</strong> &mdash; Security Researcher @ <strong>CrowdStrike</strong></span>
      </div>
      <div class="pe-disasm-row">
        <span class="pe-gutter">.text:0004</span>
        <span class="pe-comment">; I enjoy picking apart malware, everything here is reproducible if you want to follow along</span>
      </div>
      <div class="pe-disasm-row">
        <span class="pe-gutter">.text:0008</span>
        <span class="pe-comment">; Samples: <a href="https://www.virustotal.com/" target="_blank">VirusTotal</a> &middot; <a href="https://bazaar.abuse.ch/" target="_blank">MalwareBazaar</a> &middot; <a href="https://github.com/MZHeader/MZHeader.github.io/tree/main/samples" target="_blank">github.com/MZHeader/samples</a></span>
      </div>
    </div>

    <!-- Section divider -->
    <div class="pe-section-divider">
      <span class="pe-section-divider-label">Section[1]&nbsp;&nbsp;.rsrc&nbsp;&nbsp;<span class="pe-divider-detail">VirtualAddress:&nbsp;0x00004000&nbsp;&nbsp;&nbsp;VirtualSize:&nbsp;0x00001200&nbsp;&nbsp;&nbsp;</span>Characteristics:&nbsp;0x40000040</span>
    </div>

    <!-- .rsrc section -->
    <div class="pe-section-toolbar">
      <span class="pe-section-name">.rsrc</span>
      <span class="pe-section-flags" title="IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ">Characteristics: 0x40000040</span>
    </div>
    <div class="pe-section-meta" style="display:none">
    </div>
    <div class="pe-section-body">
      <div class="filter-bar" id="filterBar">
        <span class="filter-bar-label">; filter:</span>
        <button class="filter-btn active" data-cat="all">ALL</button>
        
        <button class="filter-btn" data-cat="infostealer">InfoStealer</button>
        <button class="filter-btn" data-cat="rats">RAT</button>
        <button class="filter-btn" data-cat="loader">Loader</button>
        <button class="filter-btn" data-cat="ctf">CTF</button>
      </div>
      <div id="postsList">
${posts_list_html}
      </div>
    </div>

    <!-- Section divider -->
    <div class="pe-section-divider">
      <span class="pe-section-divider-label">Section[2]&nbsp;&nbsp;.lnkin&nbsp;&nbsp;<span class="pe-divider-detail">VirtualAddress:&nbsp;0x00006000&nbsp;&nbsp;&nbsp;VirtualSize:&nbsp;0x00000200&nbsp;&nbsp;&nbsp;</span>Characteristics:&nbsp;0x00000200</span>
    </div>

    <!-- .lnkin section -->
    <div class="pe-section-toolbar">
      <span class="pe-section-name">.lnkin</span>
      <span class="pe-section-flags" title="IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_LNK_INFO">Characteristics: 0x00000200</span>
    </div>
    <div class="pe-section-body">
      <a class="rsrc-post-row" href="https://www.linkedin.com/in/liam-chugg/" target="_blank" rel="noopener noreferrer">
        <span class="rsrc-gutter">.lnkin:0000</span>
        <span class="rsrc-title">linkedin.com/in/liam-chugg</span>
      </a>
    </div>

    <!-- Section divider -->
    <div class="pe-section-divider">
      <span class="pe-section-divider-label">Section[3]&nbsp;&nbsp;.gthb&nbsp;&nbsp;<span class="pe-divider-detail">VirtualAddress:&nbsp;0x00007000&nbsp;&nbsp;&nbsp;VirtualSize:&nbsp;0x00000200&nbsp;&nbsp;&nbsp;</span>Characteristics:&nbsp;0x00000200</span>
    </div>

    <!-- .gthb section -->
    <div class="pe-section-toolbar">
      <span class="pe-section-name">.gthb</span>
      <span class="pe-section-flags" title="IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_LNK_INFO">Characteristics: 0x00000200</span>
    </div>
    <div class="pe-section-body">
      <a class="rsrc-post-row" href="https://github.com/MZHeader" target="_blank" rel="noopener noreferrer">
        <span class="rsrc-gutter">.gthb:0000</span>
        <span class="rsrc-title">github.com/MZHeader</span>
      </a>
    </div>
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

<script>
  const panel = document.getElementById('detailPanel');
  const detailBody = document.getElementById('detailBody');
  const placeholder = '<div class="pe-detail-placeholder">; hover a .rsrc entry<br>; to inspect resource data</div>';

  const postData = {};
  ${post_data_js}

  document.querySelectorAll('.rsrc-post-row').forEach(row => {
    row.addEventListener('mouseenter', () => {
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

  // ── Category filter ──
  (function() {
    var filterBar = document.getElementById('filterBar');
    var buttons = filterBar.querySelectorAll('.filter-btn');
    var rows = document.querySelectorAll('#postsList > .rsrc-post-row');
    var activeCat = 'all';

    // Map badge class suffix to filter category
    function getRowCat(row) {
      var badge = row.querySelector('.rsrc-badge');
      if (!badge) return 'analysis';
      var cls = badge.className;
      var m = cls.match(/rsrc-badge--(\w+)/);
      return m ? m[1] : 'analysis';
    }

    function applyFilter(cat) {
      activeCat = cat;
      var visibleIdx = 0;
      for (var i = 0; i < rows.length; i++) {
        var rowCat = getRowCat(rows[i]);
        var show = (cat === 'all' || rowCat === cat);
        rows[i].style.display = show ? '' : 'none';
        if (show) {
          var gutter = rows[i].querySelector('.rsrc-gutter');
          if (gutter) {
            var offset = (visibleIdx * 32).toString(16).toUpperCase();
            while (offset.length < 4) offset = '0' + offset;
            gutter.textContent = '.rsrc:' + offset;
          }
          visibleIdx++;
        }
      }
      for (var j = 0; j < buttons.length; j++) {
        buttons[j].classList.toggle('active', buttons[j].getAttribute('data-cat') === cat);
      }
    }

    filterBar.addEventListener('click', function(e) {
      var btn = e.target.closest('.filter-btn');
      if (!btn) return;
      var cat = btn.getAttribute('data-cat');
      if (cat === activeCat || cat === 'all') {
        applyFilter('all');
      } else {
        applyFilter(cat);
      }
    });
  })();
</script>


</body>
</html>
ENDINDEX

echo "Built: index.html"

# ── sitemap.xml ────────────────────────────────────────────────────────────
sitemap_entries=""
for i in $(seq 1 $total_posts); do
    sitemap_entries+="
  <url>
    <loc>https://mzheader.tech/posts/${p_slugs[$i]}.html</loc>
    <lastmod>${p_date_strs[$i]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>"
done

cat > "_site/sitemap.xml" << ENDSITEMAP
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://mzheader.tech/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>${sitemap_entries}
</urlset>
ENDSITEMAP
echo "Built: sitemap.xml"

# ── robots.txt ─────────────────────────────────────────────────────────────
cat > "_site/robots.txt" << 'ENDROBOTS'
User-agent: *
Allow: /
Sitemap: https://mzheader.tech/sitemap.xml
ENDROBOTS
echo "Built: robots.txt"

# ── 404.html ───────────────────────────────────────────────────────────────
cat > "_site/404.html" << 'END404'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>404 — MZHeader: Reverse Engineering Malware</title>
  <script>
    // Redirect old Jekyll URLs (/posts/slug) to new ones (/posts/slug.html)
    var path = window.location.pathname.replace(/\/$/, '');
    if (path.match(/^\/posts\/[^/]+$/) && !path.endsWith('.html')) {
      window.location.replace(path + '.html');
    }
  </script>
  <style>
    body { background:#1e1e1e; color:#dcdcdc; font-family:"Fira Code","Consolas",monospace; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; flex-direction:column; gap:1rem; }
    .code { color:#c62828; font-size:3rem; font-weight:700; }
    .msg { color:#555; font-size:0.9rem; }
    a { color:#8be9fd; text-decoration:none; }
    a:hover { color:#50fa7b; }
  </style>
</head>
<body>
  <div class="code">0x404</div>
  <div class="msg">; address not found</div>
  <a href="/">← cd ..</a>
</body>
</html>
END404
echo "Built: 404.html"

echo "Done. Site is in _site/"
