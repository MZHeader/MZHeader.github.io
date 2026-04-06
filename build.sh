#!/bin/bash
set -e

mkdir -p _site/posts _site/css

# Copy static assets
cp -r assets _site/ 2>/dev/null || true
cp -r samples _site/ 2>/dev/null || true
cp favicon.ico _site/ 2>/dev/null || true
cp CNAME _site/ 2>/dev/null || true
cp -r fonts _site/ 2>/dev/null || true

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
    @keyframes hex-shift { 0% { color: #5625be; } 50% { color: #8be9fd; } 100% { color: #50fa7b; } }
    a { color: #5625be; text-decoration: none; transition: letter-spacing 0.15s ease; }
    a:hover { text-decoration: underline; letter-spacing: 0.02em; animation: hex-shift 0.25s ease forwards; }
    pre code {
      display: block;
      padding: 1em;
      background: #2d2d2d;
      color: #f8f8f2;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 0.95rem;
      font-family: "Fira Code", "Consolas", monospace;
      box-shadow: 0 0 8px rgba(0, 0, 0, 0.5);
      border: 1px solid #3a3a4a;
    }
    code {
      font-family: "Fira Code", "Consolas", monospace;
      background: #2d2d2d;
      padding: 0.1em 0.3em;
      border-radius: 3px;
      font-size: 0.9em;
      border: 1px solid rgba(86, 37, 190, 0.4);
    }
    img { max-width: 100%; height: auto; border-radius: 6px; border: 1px solid #2a2a3a; box-shadow: 0 2px 12px rgba(0, 0, 0, 0.4); }
    pre { position: relative; border-top: 2px solid #5625be; border-radius: 6px; overflow: hidden; }
    blockquote { border-left: 3px solid #5625be; padding-left: 1rem; color: #aaa; margin: 1.5rem 0; }
    hr { border: none; border-top: 1px solid #2a2a3a; margin: 2rem 0; }
    .back-link {
      display: inline-block;
      margin-bottom: 2rem;
      color: #8be9fd;
      font-size: 0.9rem;
    }
    .post-meta { color: #999; font-size: 0.85rem; margin-bottom: 2rem; }
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
  <link rel="manifest" href="/manifest.json" />
  <meta name="theme-color" content="#5625be" />
  <link rel="alternate" type="application/atom+xml" title="MZHeader RSS Feed" href="/atom.xml" />
  <link rel="dns-prefetch" href="https://cdnjs.cloudflare.com" />
  <style>
    @font-face {
      font-family: "Fira Code";
      font-style: normal;
      font-weight: 400 600;
      font-display: swap;
      src: url("/fonts/FiraCode-latin.woff2") format("woff2");
    }
  </style>
'

HLJS_HEAD='
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/base16/dracula.min.css">
  <script defer src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script defer src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/x86asm.min.js" onload="hljs.highlightAll()"></script>
'

posts_list_html=""
post_data_js=""
itemlist_json=""
post_idx=0

declare -a p_slugs p_titles p_dates p_date_strs p_descs p_tags p_badge_classes p_read_times p_word_counts p_og_images p_date_modifieds

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

    # Strip the first h2 (post title) — we render it as h1 in the template instead
    python3 - <<'PYSTRIP' "/tmp/mzbuild_${slug}.html"
import sys, re
path = sys.argv[1]
content = open(path).read()
content = re.sub(r'<h2[^>]*>.*?</h2>', '', content, count=1, flags=re.DOTALL)
open(path, 'w').write(content)
PYSTRIP

    # Calculate reading time (~200 words per minute)
    word_count=$(sed -e 's/<[^>]*>//g' "/tmp/mzbuild_${slug}.html" | wc -w | tr -d ' ')
    read_time=$(( (word_count + 199) / 200 ))
    [ "$read_time" -lt 1 ] && read_time=1
    p_read_times[$post_idx]="$read_time"
    p_word_counts[$post_idx]="$word_count"

    # Extract first image URL from rendered HTML for per-post OG image
    first_img=$(grep -oE '<img[^>]+src="[^"]+"' "/tmp/mzbuild_${slug}.html" | head -1 | sed 's/.*src="//;s/".*//' || true)
    if [ -n "$first_img" ]; then
      p_og_images[$post_idx]="$first_img"
    else
      p_og_images[$post_idx]="https://mzheader.tech/assets/img/og-preview.png"
    fi

    # Get last modified date from git history for dateModified
    git_modified=$(git log -1 --format="%cs" -- "$post" 2>/dev/null || echo "$date_str")
    p_date_modifieds[$post_idx]="$git_modified"

    offset=$(printf '%04X' $(( (post_idx - 1) * 32 )) )

    js_title=$(printf '%s' "$title" | sed "s/'/\\\\'/g")
    js_desc=$(printf '%s' "$description" | sed "s/'/\\\\'/g")

    post_data_js+="postData['post-${post_idx}']={slug:'/posts/${slug}.html',title:'${js_title}',desc:'${js_desc}',date:'${date_str}',readTime:'${read_time} min read'};"

    # Build ItemList entry for homepage structured data
    il_title=$(printf '%s' "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')
    il_desc=$(printf '%s' "$description" | sed 's/\\/\\\\/g; s/"/\\"/g')
    [ -n "$itemlist_json" ] && itemlist_json+=","
    itemlist_json+="
      {
        \"@type\": \"ListItem\",
        \"position\": ${post_idx},
        \"url\": \"https://mzheader.tech/posts/${slug}.html\",
        \"name\": \"${il_title}\"
      }"

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
    read_time="${p_read_times[$i]}"
    word_count="${p_word_counts[$i]}"
    tags="${p_tags[$i]}"
    og_image="${p_og_images[$i]}"
    date_modified="${p_date_modifieds[$i]}"
    short_title="${title%%:*}"

    # JSON-escape title and description for structured data
    json_title=$(printf '%s' "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')
    json_desc=$(printf '%s' "$description" | sed 's/\\/\\\\/g; s/"/\\"/g')

    # Prev = newer post (lower index), Next = older post (higher index)
    prev_html=""
    next_html=""
    prefetch_links=""
    prev_i=$((i - 1))
    next_i=$((i + 1))
    if [ $prev_i -ge 1 ]; then
        prev_label="${p_titles[$prev_i]%%:*}"
        prev_html="<a class=\"post-pagination-link\" href=\"/posts/${p_slugs[$prev_i]}.html\">&larr; ${prev_label}</a>"
        prefetch_links+="
  <link rel=\"prefetch\" href=\"/posts/${p_slugs[$prev_i]}.html\" />"
    fi
    if [ $next_i -le $total_posts ]; then
        next_label="${p_titles[$next_i]%%:*}"
        next_html="<a class=\"post-pagination-link post-pagination-link--right\" href=\"/posts/${p_slugs[$next_i]}.html\">${next_label} &rarr;</a>"
        prefetch_links+="
  <link rel=\"prefetch\" href=\"/posts/${p_slugs[$next_i]}.html\" />"
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
  <meta property="og:image" content="${og_image}" />
  <meta property="article:published_time" content="${date_str}" />
  <meta property="article:modified_time" content="${date_modified}" />
  <meta property="article:author" content="Liam Chugg" />
  <meta property="article:section" content="Malware Analysis" />
  <meta property="article:tag" content="${tags}" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:site" content="@Chuggx00" />
  <meta name="twitter:creator" content="@Chuggx00" />
  <meta name="twitter:image" content="${og_image}" />
  <meta name="twitter:title" content="${title}" />
  <meta name="twitter:description" content="${description}" />${prefetch_links}
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
          rgba(0, 0, 0, 0.09) 2px,
          rgba(0, 0, 0, 0.09) 4px
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
    #rsrc-sidebar a.rsrc-post-row:hover,
    #rsrc-sidebar a.rsrc-post-row:focus-visible {
      background: rgba(86, 37, 190, 0.1);
      border-left-color: #5625be;
    }
    #rsrc-sidebar a.rsrc-post-row:focus-visible .rsrc-title { color: #c0c0c0; }
    #rsrc-sidebar a.rsrc-post-row:focus-visible .rsrc-title::before { opacity: 1; }
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
      color: #999;
      white-space: normal;
      overflow: visible;
      text-overflow: unset;
      line-height: 1.35;
    }
    #rsrc-sidebar a.rsrc-post-row:hover .rsrc-title { color: #c0c0c0; }
    #rsrc-sidebar .rsrc-title::before {
      content: "call  ";
      color: #e6db74;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.65rem;
      font-weight: normal;
      opacity: 0;
      transition: opacity 0.15s ease;
    }
    #rsrc-sidebar a.rsrc-post-row:hover .rsrc-title::before { opacity: 1; }
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
      max-width: 860px;
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
      color: #777;
      letter-spacing: 0.03em;
    }

    /* ── Table of contents ── */
    .toc {
      margin: 1.5rem 0;
      border: 1px solid #2a2a3a;
      border-radius: 6px;
      overflow: hidden;
      font-family: "Fira Code", "Consolas", monospace;
      background: rgba(10, 10, 16, 0.5);
    }
    .toc-trigger {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.55rem 1rem;
      cursor: pointer;
      user-select: none;
      background: #161620;
      transition: background 0.1s;
    }
    .toc-trigger:hover { background: rgba(86, 37, 190, 0.1); }
    .toc-label {
      font-size: 0.82rem;
      color: #8be9fd;
      font-weight: 600;
    }
    .toc-toggle {
      color: #5625be;
      font-size: 0.75rem;
      transition: color 0.15s;
    }
    .toc-trigger:hover .toc-toggle { color: #8be9fd; }
    .toc-body {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.35s ease;
    }
    .toc-body.open {
      max-height: 80rem;
    }
    .toc-body ul {
      list-style: none;
      margin: 0;
      padding: 0.4rem 1rem 0.6rem;
    }
    .toc-body ul ul.toc-sublist {
      padding: 0 0 0.3rem 1rem;
    }
    .toc-body li {
      padding: 0.2rem 0;
    }
    .toc-body li a {
      display: block;
      color: #999;
      text-decoration: none;
      font-size: 0.8rem;
      transition: color 0.1s;
    }
    .toc-body li a::before {
      content: "jmp  ";
      color: #e6db74;
      font-size: 0.75rem;
      opacity: 0;
      transition: opacity 0.15s ease;
    }
    .toc-body li:hover > a {
      color: #8be9fd;
      text-decoration: none;
    }
    .toc-body li:hover > a::before {
      opacity: 1;
    }
    .toc-category {
      color: #5625be;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.04em;
      padding-top: 0.5rem !important;
      padding-bottom: 0 !important;
      list-style: none;
    }
    .toc-category > span {
      display: block;
      padding-bottom: 0.15rem;
    }
    .toc-h3 { padding-left: 1rem !important; }
    .toc-h3 a { font-size: 0.75rem !important; color: #777 !important; }
    .toc-h3:hover > a { color: #8be9fd !important; }
    .toc-body li a.toc-active {
      color: #8be9fd;
    }
    .toc-body li a.toc-active::before {
      content: "► ";
      color: #5625be;
      font-size: 0.65rem;
    }
    .toc-h3 a.toc-active { color: #8be9fd !important; }

    /* ── Article ── */
    article h1 {
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
      border-left: 2px solid #3a3a4a;
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
      border-radius: 6px;
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
    article tr:nth-child(even) td { background: rgba(30, 30, 42, 0.5); }
    article tr:hover td { background: rgba(86, 37, 190, 0.07); }

    /* ── Scroll-to-top ── */
    .scroll-top-btn {
      position: fixed;
      bottom: 1.5rem;
      right: 1.5rem;
      width: 36px;
      height: 36px;
      background: rgba(16, 16, 22, 0.9);
      border: 1px solid #2a2a3a;
      border-radius: 4px;
      color: #5625be;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.75rem;
      cursor: pointer;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s, color 0.15s, border-color 0.15s;
      z-index: 90;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .scroll-top-btn.visible { opacity: 1; pointer-events: auto; }
    .scroll-top-btn:hover { color: #8be9fd; border-color: #5625be; }
    .scroll-top-btn:focus-visible { outline: 2px solid #5625be; outline-offset: 2px; }
    @media (max-width: 900px) { .scroll-top-btn { bottom: 1rem; right: 1rem; } }

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
      html, body { overflow-x: hidden; }
      body { display: block; }
      #rsrc-sidebar { display: none; }
      #post-main { margin-left: 0; max-width: 100%; padding: 3.5rem 1rem 1rem; }
      .post-nav { padding-bottom: 0.5rem; margin-bottom: 1.5rem; }
      .post-nav .back-link { display: none; }
      article h1 { font-size: 1.4rem; }
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
        color: #7a7a99;
        font-size: 0.75rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        flex: 1;
        min-width: 0;
      }
    }

    /* ── Related posts ── */
    .related-posts {
      max-width: 860px;
      margin: 2.5rem auto 0;
      padding: 1rem;
      border: 1px solid #2a2a3a;
      border-radius: 6px;
      background: rgba(10, 10, 16, 0.5);
      font-family: "Fira Code", "Consolas", monospace;
    }
    .related-label {
      display: block;
      font-size: 0.72rem;
      color: #8be9fd;
      font-weight: 600;
      letter-spacing: 0.06em;
      margin-bottom: 0.6rem;
    }
    .related-post-link {
      display: block;
      color: #999;
      text-decoration: none;
      font-family: "Segoe UI", "Roboto", sans-serif;
      font-size: 0.85rem;
      padding: 0.35rem 0.5rem;
      border-left: 2px solid transparent;
      transition: color 0.12s, border-color 0.12s, background 0.12s;
    }
    .related-post-link:hover {
      color: #8be9fd;
      border-left-color: #5625be;
      background: rgba(86, 37, 190, 0.08);
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
    .post-pagination-link:hover,
    .post-pagination-link:focus-visible { color: #50fa7b; }
    .post-pagination-link:focus-visible { outline: 2px solid #5625be; outline-offset: 3px; }

    /* ── Reading progress bar ── */
    .reading-progress {
      position: fixed;
      top: 0;
      left: 0;
      width: 0%;
      height: 2px;
      background: #5625be;
      box-shadow: 0 0 6px rgba(86, 37, 190, 0.4);
      z-index: 999;
      transition: width 0.1s linear;
    }
    @media (max-width: 900px) { .reading-progress { top: 44px; } }

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
    .pre-wrapper:hover .copy-btn,
    .pre-wrapper:focus-within .copy-btn,
    .copy-btn:focus-visible { opacity: 1; }
    .copy-btn:focus-visible { outline: 2px solid #5625be; outline-offset: 1px; }
    @media (hover: none) { .copy-btn { opacity: 1; } }
    .copy-btn.copied { color: #50fa7b; border-color: #50fa7b; }
  </style>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    "headline": "${json_title}",
    "description": "${json_desc}",
    "datePublished": "${date_str}",
    "dateModified": "${date_modified}",
    "author": {
      "@type": "Person",
      "name": "Liam Chugg",
      "url": "https://www.linkedin.com/in/liam-chugg/",
      "sameAs": [
        "https://x.com/Chuggx00",
        "https://github.com/MZHeader",
        "https://www.linkedin.com/in/liam-chugg/"
      ]
    },
    "publisher": {
      "@type": "Person",
      "name": "Liam Chugg"
    },
    "url": "https://mzheader.tech/posts/${slug}.html",
    "mainEntityOfPage": "https://mzheader.tech/posts/${slug}.html",
    "image": "${og_image}",
    "wordCount": "${word_count}",
    "articleSection": "${tags}"
  }
  </script>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    "itemListElement": [
      {
        "@type": "ListItem",
        "position": 1,
        "name": "Home",
        "item": "https://mzheader.tech/"
      },
      {
        "@type": "ListItem",
        "position": 2,
        "name": "${json_title}",
        "item": "https://mzheader.tech/posts/${slug}.html"
      }
    ]
  }
  </script>
</head>
<body>

<div class="reading-progress" id="readingProgress"></div>

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
    <a class="mob-back" href="/">&larr; ret</a>
    <span class="mob-sep">/</span>
    <span class="mob-title">${short_title}</span>
  </div>

  <div id="post-main">
    <div class="post-nav">
      <a class="back-link" href="/">&larr; ret</a>
      <span class="post-meta">${formatted_date} &middot; ${read_time} min read</span>
    </div>
    <article>
      <h1>${title}</h1>
ENDHEADER

    # ── Generate TOC ──
    toc_html=""
    # Flatten HTML to one line, split on closing h2/h3, extract level|id|text
    headings=$(tr '\n' ' ' < "/tmp/mzbuild_${slug}.html" | sed 's/<\/h[23]>/\n/g' | sed 's/.*<h\([23]\) id="\([^"]*\)">/\1|\2|/' | grep '^[23]|' | sed 's/<[^>]*>//g' || true)

    if [ -n "$headings" ]; then
      heading_count=$(echo "$headings" | wc -l | tr -d ' ')

      if [ "$heading_count" -ge 3 ]; then
        if [ "$tags" = "CTF" ]; then
          # ── CTF posts: group by category ──
          toc_inner=""
          current_cat=""
          while IFS='|' read -r hlevel hid htxt; do
            # Parse "ChallengeName | Category emoji | @Author" format
            if echo "$htxt" | grep -q '|'; then
              challenge=$(echo "$htxt" | awk -F'|' '{gsub(/^[ *]+|[ *]+$/, "", $1); print $1}')
              cat_part=$(echo "$htxt" | awk -F'|' '{gsub(/^[ ]+|[ ]+$/, "", $2); print $2}' | sed 's/[^a-zA-Z ]//g' | sed 's/^ *//;s/ *$//')
            else
              challenge="$htxt"
              cat_part=""
            fi
            if [ -n "$cat_part" ] && [ "$cat_part" != "$current_cat" ]; then
              [ -n "$current_cat" ] && toc_inner+="</ul></li>"
              current_cat="$cat_part"
              toc_inner+="<li class=\"toc-category\"><span>${current_cat}</span><ul class=\"toc-sublist\">"
            fi
            toc_inner+="<li><a href=\"#${hid}\">${challenge}</a></li>"
          done <<< "$headings"
          [ -n "$current_cat" ] && toc_inner+="</ul></li>"
          toc_html="<nav class=\"toc\" id=\"toc\"><div class=\"toc-trigger\" id=\"tocTrigger\" role=\"button\" tabindex=\"0\"><span class=\"toc-label\">; table of contents</span><span class=\"toc-toggle\" id=\"tocToggle\">[+]</span></div><div class=\"toc-body\" id=\"tocBody\"><ul>${toc_inner}</ul></div></nav>"
        else
          # ── Regular posts: flat list from h2/h3 ──
          toc_inner=""
          while IFS='|' read -r hlevel hid htxt; do
            if [ "$hlevel" = "3" ]; then
              toc_inner+="<li class=\"toc-h3\"><a href=\"#${hid}\">${htxt}</a></li>"
            else
              toc_inner+="<li><a href=\"#${hid}\">${htxt}</a></li>"
            fi
          done <<< "$headings"
          toc_html="<nav class=\"toc\" id=\"toc\"><div class=\"toc-trigger\" id=\"tocTrigger\" role=\"button\" tabindex=\"0\"><span class=\"toc-label\">; table of contents</span><span class=\"toc-toggle\" id=\"tocToggle\">[+]</span></div><div class=\"toc-body\" id=\"tocBody\"><ul>${toc_inner}</ul></div></nav>"
        fi
      fi
    fi

    # Write TOC if generated
    if [ -n "$toc_html" ]; then
      printf '%s' "$toc_html" >> "_site/posts/${slug}.html"
    fi

    cat "/tmp/mzbuild_${slug}.html" >> "_site/posts/${slug}.html"

    # ── Build related posts by matching tag ──
    related_html=""
    related_count=0
    for ri in $(seq 1 $total_posts); do
      [ "$ri" -eq "$i" ] && continue
      [ "$related_count" -ge 3 ] && break
      if [ "${p_tags[$ri]}" = "${tags}" ]; then
        related_html+="<a class=\"related-post-link\" href=\"/posts/${p_slugs[$ri]}.html\">${p_titles[$ri]}</a>"
        related_count=$((related_count + 1))
      fi
    done
    related_section=""
    if [ -n "$related_html" ]; then
      related_section="<div class=\"related-posts\"><span class=\"related-label\">; related ${tags} posts</span>${related_html}</div>"
    fi

    cat >> "_site/posts/${slug}.html" << ENDFOOTER
    </article>
    ${related_section}
    <nav class="post-pagination">
      ${prev_html}
      ${next_html}
    </nav>
  </div>

<button class="scroll-top-btn" id="scrollTopBtn" aria-label="Scroll to top" title="0x0000">^</button>

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

  // ── TOC toggle ──
  var tocTrigger = document.getElementById("tocTrigger");
  var tocBody = document.getElementById("tocBody");
  var tocToggle = document.getElementById("tocToggle");
  if (tocTrigger && tocBody && tocToggle) {
    tocTrigger.addEventListener("click", function() {
      var open = tocBody.classList.toggle("open");
      tocToggle.textContent = open ? "[-]" : "[+]";
    });
    tocTrigger.addEventListener("keydown", function(e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); tocTrigger.click(); }
    });
  }

  // ── Scroll-spy for TOC ──
  if (tocBody) {
    var tocLinks = tocBody.querySelectorAll("a[href^='#']");
    var headingEls = [];
    tocLinks.forEach(function(link) {
      var id = link.getAttribute("href").slice(1);
      var el = document.getElementById(id);
      if (el) headingEls.push({ el: el, link: link });
    });
    if (headingEls.length > 0) {
      var spyActive = null;
      function updateSpy() {
        var scrollY = window.scrollY || document.documentElement.scrollTop;
        var current = null;
        for (var i = 0; i < headingEls.length; i++) {
          if (headingEls[i].el.offsetTop - 120 <= scrollY) current = i;
        }
        if (current !== spyActive) {
          if (spyActive !== null) headingEls[spyActive].link.classList.remove("toc-active");
          if (current !== null) headingEls[current].link.classList.add("toc-active");
          spyActive = current;
        }
      }
      var spyTimer;
      window.addEventListener("scroll", function() {
        if (spyTimer) return;
        spyTimer = requestAnimationFrame(function() { updateSpy(); spyTimer = null; });
      });
      updateSpy();
    }
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

  // ── Reading progress bar + Scroll-to-top button ──
  var progressBar = document.getElementById('readingProgress');
  var scrollBtn = document.getElementById('scrollTopBtn');
  var scrollTimer2;
  window.addEventListener('scroll', function() {
    if (scrollTimer2) return;
    scrollTimer2 = requestAnimationFrame(function() {
      var scrollTop = window.scrollY || document.documentElement.scrollTop;
      var docHeight = document.documentElement.scrollHeight - window.innerHeight;
      if (progressBar && docHeight > 0) {
        progressBar.style.width = Math.min(100, (scrollTop / docHeight) * 100) + '%';
      }
      if (scrollBtn) {
        scrollBtn.classList.toggle('visible', scrollTop > window.innerHeight);
      }
      scrollTimer2 = null;
    });
  });
  if (scrollBtn) {
    scrollBtn.addEventListener('click', function() {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }
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
  <meta property="og:image" content="https://mzheader.tech/assets/img/og-preview.png" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:site" content="@Chuggx00" />
  <meta name="twitter:creator" content="@Chuggx00" />
  <meta name="twitter:image" content="https://mzheader.tech/assets/img/og-preview.png" />
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
          rgba(0, 0, 0, 0.09) 2px,
          rgba(0, 0, 0, 0.09) 4px
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
      color: #666;
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
      color: #999;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .pe-window-titlebar .window-title .wt-app { color: #5625be; }
    .pe-window-titlebar .window-title .wt-sep { color: #333; margin: 0 0.3em; }
    .pe-window-titlebar .window-title .wt-file { color: #c62828; }
    .pe-window-titlebar .window-title .wt-path { color: #666; }
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
      color: #666;
    }
    .pe-section-toolbar .pe-section-name { color: #8be9fd; font-weight: 600; }
    .pe-section-toolbar .pe-section-flags { color: #666; font-size: 0.72rem; }

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
      border-left: 3px solid transparent;
      white-space: nowrap;
      overflow: hidden;
    }
    .pe-section-divider--text { border-left-color: #5625be; }
    .pe-section-divider--rsrc { border-left-color: #8be9fd; }
    .pe-section-divider--idata { border-left-color: #50fa7b; }
    .pe-section-divider-label {
      font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
      font-size: 0.72rem;
      color: #4a4a6a;
      letter-spacing: 0.04em;
    }
    .pe-section-divider-label .pe-divider-detail {
      color: #4a4a6a;
    }
    @media (max-width: 600px) {
      .pe-section-divider-label .pe-divider-detail {
        display: none;
      }
    }

    @keyframes hex-shift { 0% { color: #5625be; } 50% { color: #8be9fd; } 100% { color: #50fa7b; } }

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
      color: #5a5a7a;
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
    .pe-operand a { color: #8be9fd !important; transition: letter-spacing 0.15s ease; }
    .pe-operand a:hover { color: #50fa7b !important; letter-spacing: 0.02em; animation: hex-shift 0.25s ease forwards; }
    .pe-comment {
      flex: 1;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.88rem;
      color: #8888b0;
      line-height: 1.65;
    }
    .pe-comment strong { color: #c62828; font-weight: 600; }
    .pe-comment a { color: #8be9fd !important; transition: letter-spacing 0.15s ease; }
    .pe-comment a:hover { color: #50fa7b !important; letter-spacing: 0.02em; animation: hex-shift 0.25s ease forwards; }

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
    .rsrc-post-row:hover,
    .rsrc-post-row:focus-visible {
      background: rgba(86, 37, 190, 0.10);
      border-left-color: #5625be;
      text-decoration: none;
    }
    .rsrc-post-row:focus-visible .rsrc-gutter { color: #5625be; }
    .rsrc-post-row:focus-visible .rsrc-title {
      color: #8be9fd;
      text-shadow: 0 0 8px rgba(139, 233, 253, 0.3);
    }
    .rsrc-post-row:focus-visible .rsrc-meta { color: #6e6e90; }
    /* Staggered entrance animation for post rows */
    @keyframes row-enter {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .rsrc-post-row {
      animation: row-enter 0.2s ease both;
    }
    @media (prefers-reduced-motion: reduce) {
      .rsrc-post-row { animation: none; }
    }

    /* Scroll-aware gutter highlight */
    .rsrc-post-row .rsrc-gutter.gutter-near {
      color: #8be9fd;
      text-shadow: 0 0 6px rgba(139, 233, 253, 0.25);
      transition: color 0.2s ease, text-shadow 0.2s ease;
    }

    .rsrc-post-row .rsrc-gutter {
      width: 7em;
      flex-shrink: 0;
      color: #5a5a7a;
      font-size: 0.82rem;
      user-select: none;
      padding-top: 0.15rem;
      transition: color 0.2s ease, text-shadow 0.2s ease;
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
    .rsrc-post-row .rsrc-title::before {
      content: "call  ";
      color: #e6db74;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.82rem;
      font-weight: normal;
      opacity: 0;
      transition: opacity 0.15s ease;
    }
    .rsrc-post-row:hover .rsrc-title::before,
    .rsrc-post-row:focus-visible .rsrc-title::before {
      opacity: 1;
    }
    .rsrc-post-row:hover .rsrc-title {
      color: #8be9fd;
      text-shadow: 0 0 8px rgba(139, 233, 253, 0.3);
    }
    .rsrc-meta {
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.74rem;
      color: #7a7a99;
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

    /* Social link hover glow */
    .rsrc-post-row[target="_blank"]:hover .rsrc-title {
      color: #8be9fd;
      text-shadow: 0 0 8px rgba(139, 233, 253, 0.3);
    }
    .rsrc-post-row[target="_blank"]:hover .rsrc-gutter {
      color: #5625be;
    }

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
      border-radius: 6px;
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
      color: #666;
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
    .pe-detail-panel.active .pe-detail-desc { color: #999; }
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
      transition: background 0.12s, color 0.12s, border-color 0.12s, box-shadow 0.12s, transform 0.12s;
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
      transform: scale(1.03);
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
    .filter-btn:focus-visible {
      outline: 2px solid #5625be;
      outline-offset: 1px;
    }

    /* Skip-to-content link */
    .skip-link {
      position: absolute;
      top: -100%;
      left: 1rem;
      padding: 0.5rem 1rem;
      background: #5625be;
      color: #fff;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.8rem;
      border-radius: 0 0 4px 4px;
      z-index: 1000;
      text-decoration: none;
    }
    .skip-link:focus {
      top: 0;
    }

    /* General focus-visible for interactive elements */
    .about-trigger:focus-visible {
      outline: 2px solid #5625be;
      outline-offset: -2px;
    }

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
      .about-toggle { font-size: 0.6rem; }
    }

    /* Reduced motion preference */
    @media (prefers-reduced-motion: reduce) {
      .title-malware { animation: none !important; }
      .magnifier { display: none !important; }
      .re-char.scrambling { color: inherit; opacity: inherit; }
    }

    /* About Me expandable panel */
    .about-trigger {
      display: flex;
      padding: 0.3rem 1rem;
      line-height: 1.7;
      transition: background 0.1s ease;
      cursor: pointer;
      user-select: none;
      border-left: 2px solid #5625be;
    }
    .about-trigger:hover { background: rgba(86, 37, 190, 0.10); }
    .about-trigger:hover .pe-comment::before {
      content: "je    ";
      color: #e6db74;
      font-size: 0.82rem;
    }
    .about-trigger.open:hover .pe-comment::before {
      content: "jne   ";
    }
    .about-trigger .pe-comment { flex: 1; color: #c0c0e0; cursor: pointer; }
    .about-trigger.open .pe-comment { color: #8be9fd; }
    .about-toggle {
      color: #5625be;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.75rem;
      transition: color 0.15s ease, transform 0.25s ease;
      flex-shrink: 0;
      padding-top: 0.15em;
    }
    .about-trigger:hover .about-toggle { color: #8be9fd; }
    .about-trigger.open .about-toggle { color: #8be9fd; }

    .about-expanded {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.35s ease;
      border-left: 2px solid #5625be;
      background: rgba(0, 0, 0, 0.2);
    }
    .about-expanded.open {
      max-height: 30rem;
    }
    .about-expanded .pe-disasm-row {
      background: transparent;
    }
    .about-sep {
      color: #2a2a3a !important;
    }

  </style>
  <script type="application/ld+json">
  [
    {
      "@context": "https://schema.org",
      "@type": "WebSite",
      "name": "MZHeader: Reverse Engineering Malware",
      "description": "Malware analysis blog by Liam Chugg, Security Researcher at CrowdStrike.",
      "url": "https://mzheader.tech/",
      "author": {
        "@type": "Person",
        "name": "Liam Chugg",
        "jobTitle": "Security Researcher",
        "worksFor": {
          "@type": "Organization",
          "name": "CrowdStrike"
        },
        "url": "https://www.linkedin.com/in/liam-chugg/",
        "sameAs": [
          "https://x.com/Chuggx00",
          "https://github.com/MZHeader",
          "https://www.linkedin.com/in/liam-chugg/"
        ]
      }
    },
    {
      "@context": "https://schema.org",
      "@type": "ItemList",
      "itemListElement": [${itemlist_json}
      ]
    }
  ]
  </script>
</head>
<body>

<a href="#postsList" class="skip-link">Skip to posts</a>

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
      <span class="window-title"><span class="wt-app">pe-viewer</span><span class="wt-sep">&#8212;</span><span class="wt-path">C:\Samples\</span><span class="wt-file">mzheader</span></span>
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
      <div class="about-trigger" id="aboutTrigger" role="button" tabindex="0" aria-expanded="false">
        <span class="pe-gutter">.text:000C</span>
        <span class="pe-comment">; &rarr; more about me</span>
        <span class="about-toggle" id="aboutToggleIcon">&#x25BC;</span>
      </div>
      <div class="about-expanded" id="aboutPanel">
        <div class="pe-disasm-row">
          <span class="pe-gutter">.text:0010</span>
          <span class="pe-comment about-sep">; ────────────────────────────────────────────────────────</span>
        </div>
        <div class="pe-disasm-row">
          <span class="pe-gutter">.text:0014</span>
          <span class="pe-comment">; Hey! I&apos;m Liam, a Security Researcher at CrowdStrike. I originally started this blog while working as a security analyst, mainly as a way to get into reverse engineering by sharpening my skills and developing my technical writing ability. Over time it&apos;s grown into a place where I share things I find interesting, from CTF / CrackMe challenges to deep dives on random malware samples.</span>
        </div>
        <div class="pe-disasm-row">
          <span class="pe-gutter">.text:0030</span>
          <span class="pe-comment about-sep">; ────────────────────────────────────────────────────────</span>
        </div>
      </div>
    </div>

    <!-- Section divider -->
    <div class="pe-section-divider pe-section-divider--rsrc">
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
        <button class="filter-btn active" data-cat="all" aria-pressed="true">ALL</button>

        <button class="filter-btn" data-cat="infostealer" aria-pressed="false">InfoStealer</button>
        <button class="filter-btn" data-cat="rats" aria-pressed="false">RAT</button>
        <button class="filter-btn" data-cat="loader" aria-pressed="false">Loader</button>
        <button class="filter-btn" data-cat="ctf" aria-pressed="false">CTF</button>
      </div>
      <div id="postsList">
${posts_list_html}
      </div>
    </div>

    <!-- Section divider -->
    <div class="pe-section-divider pe-section-divider--idata">
      <span class="pe-section-divider-label">Section[2]&nbsp;&nbsp;.idata&nbsp;&nbsp;<span class="pe-divider-detail">VirtualAddress:&nbsp;0x00006000&nbsp;&nbsp;&nbsp;VirtualSize:&nbsp;0x00000600&nbsp;&nbsp;&nbsp;</span>Characteristics:&nbsp;0x40000040</span>
    </div>

    <!-- .idata section — external links -->
    <div class="pe-section-toolbar">
      <span class="pe-section-name">.idata</span>
      <span class="pe-section-flags" title="IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ">Characteristics: 0x40000040</span>
    </div>
    <div class="pe-section-body">
      <a class="rsrc-post-row" href="https://www.linkedin.com/in/liam-chugg/" target="_blank" rel="noopener noreferrer">
        <span class="rsrc-gutter">.idata:0000</span>
        <span class="rsrc-title">linkedin.com/in/liam-chugg</span>
      </a>
      <a class="rsrc-post-row" href="https://github.com/MZHeader" target="_blank" rel="noopener noreferrer">
        <span class="rsrc-gutter">.idata:0020</span>
        <span class="rsrc-title">github.com/MZHeader</span>
      </a>
      <a class="rsrc-post-row" href="https://x.com/Chuggx00" target="_blank" rel="noopener noreferrer">
        <span class="rsrc-gutter">.idata:0040</span>
        <span class="rsrc-title">x.com/Chuggx00</span>
      </a>
      <a class="rsrc-post-row" href="/atom.xml" target="_blank" rel="noopener noreferrer">
        <span class="rsrc-gutter">.idata:0060</span>
        <span class="rsrc-title">atom.xml (RSS feed)</span>
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

  function showDetail(row) {
    const data = postData[row.id];
    if (data) {
      panel.classList.add('active');
      detailBody.innerHTML =
        '<div class="pe-detail-title">' + data.title + '</div>' +
        '<div class="pe-detail-desc">' + data.desc + '</div>' +
        '<div class="pe-detail-date"><span class="meta-label">TimeDateStamp:</span> <span class="meta-value">' + data.date + '</span></div>' +
        '<div class="pe-detail-date" style="border-top:none;margin-top:0;padding-top:0.2rem;"><span class="meta-label">ReadTime:</span> <span class="meta-value">' + data.readTime + '</span></div>';
    }
  }
  function hideDetail() { panel.classList.remove('active'); }

  document.querySelectorAll('.rsrc-post-row').forEach(row => {
    row.addEventListener('mouseenter', () => showDetail(row));
    row.addEventListener('mouseleave', hideDetail);
    row.addEventListener('focus', () => showDetail(row));
    row.addEventListener('blur', hideDetail);
  });

  (function() {
    var prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const reEl = document.getElementById('titleRE');
    const reText = 'Reverse Engineering';
    const hexChars = '0123456789ABCDEF';
    reEl.innerHTML = reText.split('').map(c =>
      c === ' ' ? ' ' : '<span class="re-char" data-c="' + c + '">' + c + '</span>'
    ).join('');

    if (!prefersReducedMotion) {
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
    }

    if (!prefersReducedMotion) {
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
    }
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

    var prefersRM = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

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
          if (!prefersRM) {
            rows[i].style.animation = 'none';
            rows[i].offsetHeight;
            rows[i].style.animation = '';
            rows[i].style.animationDelay = (visibleIdx * 35) + 'ms';
          }
          visibleIdx++;
        }
      }
      for (var j = 0; j < buttons.length; j++) {
        var isActive = buttons[j].getAttribute('data-cat') === cat;
        buttons[j].classList.toggle('active', isActive);
        buttons[j].setAttribute('aria-pressed', isActive ? 'true' : 'false');
      }
      // Clear animation after stagger completes
      if (!prefersRM) {
        var filterDelay = visibleIdx * 35 + 200;
        setTimeout(function() {
          for (var i = 0; i < rows.length; i++) {
            rows[i].style.animation = 'none';
          }
        }, filterDelay);
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

    // Initial stagger on page load
    if (!prefersRM) {
      for (var k = 0; k < rows.length; k++) {
        rows[k].style.animationDelay = (k * 35) + 'ms';
      }
      // Clear animation after all rows have entered so it doesn't replay
      var lastDelay = rows.length * 35 + 200;
      setTimeout(function() {
        for (var k = 0; k < rows.length; k++) {
          rows[k].style.animation = 'none';
        }
      }, lastDelay);
    }

    // Scroll-aware gutter highlight — row nearest viewport center glows
    var gutterTimer;
    function updateGutterHighlight() {
      var viewMid = window.innerHeight / 2;
      var closest = null;
      var closestDist = Infinity;
      for (var i = 0; i < rows.length; i++) {
        if (rows[i].style.display === 'none') continue;
        var rect = rows[i].getBoundingClientRect();
        var rowMid = rect.top + rect.height / 2;
        var dist = Math.abs(rowMid - viewMid);
        if (dist < closestDist) { closestDist = dist; closest = i; }
      }
      for (var i = 0; i < rows.length; i++) {
        var g = rows[i].querySelector('.rsrc-gutter');
        if (g) g.classList.toggle('gutter-near', i === closest);
      }
    }
    window.addEventListener('scroll', function() {
      if (gutterTimer) return;
      gutterTimer = requestAnimationFrame(function() { updateGutterHighlight(); gutterTimer = null; });
    });
    updateGutterHighlight();
  })();
</script>

<script>
  (function() {
    var trigger = document.getElementById('aboutTrigger');
    var panel = document.getElementById('aboutPanel');
    var icon = document.getElementById('aboutToggleIcon');
    if (!trigger || !panel || !icon) return;
    trigger.addEventListener('click', function() {
      var open = panel.classList.toggle('open');
      trigger.classList.toggle('open', open);
      icon.textContent = open ? '[-]' : '[+]';
      trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    trigger.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); trigger.click(); }
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
    # Extract image URLs from rendered post for image sitemap
    image_entries=""
    if [ -f "/tmp/mzbuild_${p_slugs[$i]}.html" ]; then
      while IFS= read -r img_url; do
        image_entries+="
    <image:image><image:loc>${img_url}</image:loc></image:image>"
      done < <(grep -oE '<img[^>]+src="[^"]+"' "/tmp/mzbuild_${p_slugs[$i]}.html" 2>/dev/null | sed 's/.*src="//;s/".*//' || true)
    fi
    sitemap_entries+="
  <url>
    <loc>https://mzheader.tech/posts/${p_slugs[$i]}.html</loc>
    <lastmod>${p_date_modifieds[$i]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>${image_entries}
  </url>"
done

cat > "_site/sitemap.xml" << ENDSITEMAP
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
  <url>
    <loc>https://mzheader.tech/</loc>
    <lastmod>${p_date_strs[1]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>${sitemap_entries}
</urlset>
ENDSITEMAP
echo "Built: sitemap.xml"

# ── atom.xml (RSS feed) ───────────────────────────────────────────────────
feed_entries=""
for i in $(seq 1 $total_posts); do
    escaped_title=$(printf '%s' "${p_titles[$i]}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    escaped_desc=$(printf '%s' "${p_descs[$i]}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
    feed_entries+="
  <entry>
    <title>${escaped_title}</title>
    <link href=\"https://mzheader.tech/posts/${p_slugs[$i]}.html\" rel=\"alternate\" />
    <id>https://mzheader.tech/posts/${p_slugs[$i]}.html</id>
    <published>${p_date_strs[$i]}T00:00:00Z</published>
    <updated>${p_date_strs[$i]}T00:00:00Z</updated>
    <summary>${escaped_desc}</summary>
    <author><name>Liam Chugg</name></author>
    <category term=\"${p_tags[$i]}\" />
  </entry>"
done

cat > "_site/atom.xml" << ENDFEED
<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>MZHeader: Reverse Engineering Malware</title>
  <subtitle>Malware analysis blog by Liam Chugg</subtitle>
  <link href="https://mzheader.tech/" rel="alternate" />
  <link href="https://mzheader.tech/atom.xml" rel="self" />
  <id>https://mzheader.tech/</id>
  <updated>${p_date_strs[1]}T00:00:00Z</updated>
  <author><name>Liam Chugg</name></author>${feed_entries}
</feed>
ENDFEED
echo "Built: atom.xml"

# ── robots.txt ─────────────────────────────────────────────────────────────
cat > "_site/robots.txt" << 'ENDROBOTS'
User-agent: *
Allow: /
Sitemap: https://mzheader.tech/sitemap.xml
ENDROBOTS
echo "Built: robots.txt"


# ── manifest.json ─────────────────────────────────────────────────────────
cat > "_site/manifest.json" << 'ENDMANIFEST'
{
  "name": "MZHeader: Reverse Engineering Malware",
  "short_name": "MZHeader",
  "description": "Malware analysis blog by Liam Chugg",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#1e1e1e",
  "theme_color": "#5625be",
  "icons": [
    {
      "src": "/favicon.ico",
      "sizes": "any",
      "type": "image/x-icon"
    }
  ]
}
ENDMANIFEST
echo "Built: manifest.json"

# ── 404.html ───────────────────────────────────────────────────────────────
cat > "_site/404.html" << 'END404'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>404 — MZHeader: Reverse Engineering Malware</title>
  <link rel="icon" href="/favicon.ico" />
  <style>
    @font-face {
      font-family: "Fira Code";
      font-style: normal;
      font-weight: 400 600;
      font-display: swap;
      src: url("/fonts/FiraCode-latin.woff2") format("woff2");
    }
  </style>
  <script>
    // Redirect old Jekyll URLs (/posts/slug) to new ones (/posts/slug.html)
    var path = window.location.pathname.replace(/\/$/, '');
    if (path.match(/^\/posts\/[^/]+$/) && !path.endsWith('.html')) {
      window.location.replace(path + '.html');
    }
  </script>
  <style>
    body {
      background-color:#1e1e1e;
      background-image:
        radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.45) 100%),
        repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.09) 2px, rgba(0,0,0,0.09) 4px);
      color:#dcdcdc; font-family:"Fira Code","Consolas",monospace; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; flex-direction:column; gap:0;
    }
    .pe-box { border:1px solid #2a2a3a; border-radius:6px; overflow:hidden; background:rgba(10,10,16,0.7); max-width:480px; width:90%; }
    .pe-titlebar { display:flex; align-items:center; padding:0.4rem 0.75rem; background:#12121a; border-bottom:1px solid #2a2a3a; font-size:0.72rem; color:#666; gap:0.6rem; }
    .pe-dots { display:flex; gap:5px; margin-right:0.3rem; }
    .pe-dot { width:7px; height:7px; border-radius:50%; background:#555; }
    .pe-dot.close { background:#c62828; box-shadow:0 0 4px rgba(198,40,40,0.5); }
    .pe-body { padding:0; }
    .code { color:#c62828; font-size:2.4rem; font-weight:700; text-shadow:0 0 8px rgba(198,40,40,0.4); margin-bottom:0.4rem; animation: glitch 6s infinite; }
    @keyframes glitch {
      0%,88%,100% { text-shadow:0 0 8px rgba(198,40,40,0.4); transform:translate(0); }
      90% { text-shadow:-2px 0 #8be9fd, 2px 0 #8be9fd; transform:translate(-2px,0); }
      92% { text-shadow:2px 0 #8be9fd, -2px 0 #8be9fd; transform:translate(2px,0); }
      94% { text-shadow:-1px 0 #c62828, 1px 0 #8be9fd; transform:translate(-1px,-1px); }
      96% { text-shadow:0 0 8px rgba(198,40,40,0.4); transform:translate(0); }
    }
    @media (prefers-reduced-motion: reduce) { .code { animation:none; } }
    .disasm { padding:0.8rem 1rem; }
    .disasm-row { display:flex; padding:0.25rem 0; line-height:1.7; }
    .gutter { width:6em; flex-shrink:0; color:#5a5a7a; font-size:0.78rem; user-select:none; }
    .instr { color:#5625be; width:3em; flex-shrink:0; font-size:0.82rem; }
    .operand { color:#e4e4e4; font-size:0.82rem; }
    .comment { color:#8888b0; font-size:0.82rem; }
    .comment strong { color:#c62828; font-weight:600; }
    .sep { color:#2a2a3a; padding:0.1rem 0; font-size:0.78rem; }
    .ret-row { padding:0.6rem 1rem 0.8rem; border-top:1px solid #1e1e28; }
    a { color:#50fa7b; text-decoration:none; font-size:0.82rem; text-shadow:0 0 6px rgba(80,250,123,0.3); transition: text-shadow 0.15s; }
    a:hover { text-shadow:0 0 10px rgba(80,250,123,0.6); }
    a:focus-visible { outline:2px solid #5625be; outline-offset:2px; }
  </style>
</head>
<body>
  <div class="pe-box">
    <div class="pe-titlebar">
      <div class="pe-dots">
        <span class="pe-dot close"></span>
        <span class="pe-dot"></span>
        <span class="pe-dot"></span>
      </div>
      <span style="color:#c62828">pe-viewer</span><span style="color:#333;margin:0 0.3em">&#8212;</span><span>exception handler</span>
    </div>
    <div class="pe-body">
      <div class="disasm">
        <div class="disasm-row"><span class="gutter">:0000</span><span class="comment">; <strong>STATUS_SECTION_NOT_FOUND</strong></span></div>
        <div class="disasm-row"><span class="gutter">:0004</span><span class="comment">; the requested RVA does not map to any section</span></div>
        <div class="sep">&nbsp;</div>
        <div class="disasm-row"><span class="gutter">:0008</span><span class="instr">push</span><span class="operand"><span style="color:#c62828">0x404</span></span></div>
        <div style="text-align:center;padding:0.3rem 0;">
          <div class="code">0x00000404</div>
        </div>
        <div class="disasm-row"><span class="gutter">:000D</span><span class="instr">call</span><span class="operand" style="color:#e6db74">RaiseException</span></div>
        <div class="disasm-row"><span class="gutter">:0012</span><span class="instr">xor</span><span class="operand">eax, eax</span></div>
        <div class="disasm-row"><span class="gutter">:0014</span><span class="instr">ret</span><span class="comment">; <a href="/">back to posts</a></span></div>
      </div>
    </div>
  </div>
</body>
</html>
END404
echo "Built: 404.html"

echo "Done. Site is in _site/"
