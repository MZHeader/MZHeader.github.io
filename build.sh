#!/bin/bash
set -e

mkdir -p _site/posts _site/css

# Copy static assets
cp -r assets _site/ 2>/dev/null || true
cp -r samples _site/ 2>/dev/null || true
cp favicon.ico _site/ 2>/dev/null || true
cp CNAME _site/ 2>/dev/null || true
cp -r fonts _site/ 2>/dev/null || true
cp -r css _site/ 2>/dev/null || true

SHARED_CSS='
    * { box-sizing: border-box; }
    body {
      background: #1e1e1e;
      color: #dcdcdc;
      font-family: system-ui, -apple-system, "Segoe UI", "Roboto", sans-serif;
      padding: 2rem;
      line-height: 1.6;
      max-width: 900px;
      margin: 0 auto;
    }
    h1, h2, h3, h4 { color: #7880d8; }
    a { color: #6870c4; text-decoration: none; transition: color 0.15s ease; }
    a:hover { text-decoration: underline; color: #8be9fd; }
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
      border: 1px solid rgba(104, 112, 196, 0.4);
    }
    img { max-width: 100%; height: auto; border-radius: 6px; border: 1px solid #2a2a3a; box-shadow: 0 2px 12px rgba(0, 0, 0, 0.4); }
    pre { position: relative; border-top: 2px solid #6870c4; border-radius: 6px; overflow: hidden; }
    blockquote { border-left: 3px solid #6870c4; padding-left: 1rem; color: #aaa; margin: 1.5rem 0; }
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
  <meta name="theme-color" content="#6870c4" />
  <link rel="alternate" type="application/atom+xml" title="MZHeader RSS Feed" href="/atom.xml" />
  <link rel="dns-prefetch" href="https://cdnjs.cloudflare.com" />
  <link rel="preload" as="font" type="font/woff2" href="/fonts/FiraCode-latin.woff2" crossorigin />
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
  <link rel="stylesheet" href="/css/hljs-theme.css">
  <script defer src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script defer src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/powershell.min.js"></script>
  <script defer src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/vbscript.min.js"></script>
  <script defer src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/applescript.min.js"></script>
  <script defer src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/x86asm.min.js" onload="hljs.highlightAll()"></script>
'

posts_list_html=""
post_data_js=""
itemlist_json=""
post_idx=0

declare -a p_slugs p_titles p_dates p_date_strs p_descs p_tags p_badge_classes p_read_times p_word_counts p_og_images p_date_modifieds p_series p_series_descs p_offsets p_hex_ts p_short_dates

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
    series=$(awk 'BEGIN{f=0} /^---/{f++; next} f==1 && /^series:/{sub(/^series: */, ""); gsub(/^"|"$/, ""); print; exit}' "$post")
    series_desc=$(awk 'BEGIN{f=0} /^---/{f++; next} f==1 && /^series_desc:/{sub(/^series_desc: */, ""); gsub(/^"|"$/, ""); print; exit}' "$post")
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
    p_series[$post_idx]="$series"
    p_series_descs[$post_idx]="$series_desc"

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
      case "$first_img" in
        /*) first_img="https://mzheader.tech${first_img}" ;;
      esac
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

    # Store per-post row data for series grouping (built after loop)
    p_offsets[$post_idx]="$offset"
    p_hex_ts[$post_idx]="$hex_ts"
    p_short_dates[$post_idx]="$short_date"
done

total_posts=$post_idx

# ── Build posts_list_html with series grouping ───────────────────────────
# Track which series we've already emitted (pipe-delimited string for bash 3 compat)
_series_emitted="|"
visible_row=0
for i in $(seq 1 $total_posts); do
    series="${p_series[$i]}"
    if [ -n "$series" ]; then
        # Part of a series — check if we already emitted the group header
        if [[ "$_series_emitted" != *"|${series}|"* ]]; then
            _series_emitted="${_series_emitted}${series}|"
            # Find all posts in this series (in current sorted order)
            series_count=0
            series_children=""
            series_tag=""
            series_badge=""
            series_sdesc=""
            for j in $(seq 1 $total_posts); do
                if [ "${p_series[$j]}" = "$series" ]; then
                    series_count=$((series_count + 1))
                    [ -z "$series_tag" ] && series_tag="${p_tags[$j]}"
                    [ -z "$series_badge" ] && series_badge="${p_badge_classes[$j]}"
                    [ -z "$series_sdesc" ] && series_sdesc="${p_series_descs[$j]}"
                    series_children+="
              <a class=\"rsrc-post-row series-child\" id=\"post-${j}\" href=\"/posts/${p_slugs[$j]}.html\">
                <span class=\"rsrc-gutter\">.rsrc:${p_offsets[$j]}</span>
                <span class=\"rsrc-title-block\">
                  <span class=\"rsrc-title\">${p_titles[$j]}</span>
                  <span class=\"rsrc-meta\">; TimeDateStamp: ${p_hex_ts[$j]} (${p_short_dates[$j]}) &nbsp;&middot;&nbsp; <span class=\"rsrc-badge ${p_badge_classes[$j]}\">${p_tags[$j]}</span></span>
                </span>
              </a>"
                fi
            done
            # Emit collapsible series group — header looks like a normal row
            series_noun="posts"
            [ "$series_count" -eq 1 ] && series_noun="post"
            series_id=$(printf '%s' "$series" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')
            header_offset=$(printf '%04X' $(( visible_row * 32 )) )
            visible_row=$((visible_row + 1))

            # Add series to detail panel hover data
            js_stitle=$(printf '%s' "$series" | sed "s/'/\\\\'/g")
            js_sdesc=$(printf '%s' "$series_sdesc" | sed "s/'/\\\\'/g")
            post_data_js+="postData['series-${series_id}']={title:'${js_stitle}',desc:'${js_sdesc}',series:true,count:${series_count}};"

            posts_list_html+="
          <div class=\"series-group\" data-series=\"${series_id}\" data-tag=\"${series_tag}\">
            <div class=\"series-header\" id=\"series-${series_id}\" onclick=\"toggleSeries('${series_id}')\">
              <span class=\"rsrc-gutter\">.rsrc:${header_offset}</span>
              <span class=\"rsrc-title-block\">
                <span class=\"rsrc-title\"><span class=\"series-label\">Series:</span> ${series}</span>
                <span class=\"rsrc-meta\">; ${series_count} ${series_noun} &nbsp;&middot;&nbsp; <span class=\"rsrc-badge ${series_badge}\">${series_tag}</span> &nbsp;<span class=\"series-toggle\" id=\"toggle-${series_id}\">[+]</span></span>
              </span>
            </div>
            <div class=\"series-children\" id=\"children-${series_id}\" style=\"display:none;\">
              ${series_children}
            </div>
          </div>"
        fi
        # Skip — already emitted as part of series group
    else
        # Standalone post (no series)
        visible_row=$((visible_row + 1))
        posts_list_html+="
      <a class=\"rsrc-post-row\" id=\"post-${i}\" href=\"/posts/${p_slugs[$i]}.html\">
        <span class=\"rsrc-gutter\">.rsrc:${p_offsets[$i]}</span>
        <span class=\"rsrc-title-block\">
          <span class=\"rsrc-title\">${p_titles[$i]}</span>
          <span class=\"rsrc-meta\">; TimeDateStamp: ${p_hex_ts[$i]} (${p_short_dates[$i]}) &nbsp;&middot;&nbsp; <span class=\"rsrc-badge ${p_badge_classes[$i]}\">${p_tags[$i]}</span></span>
        </span>
      </a>"
    fi
done

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
  <meta name="robots" content="index,follow,max-image-preview:large" />
  <meta name="color-scheme" content="dark" />
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

    /* ── Skip-to-content link ── */
    .skip-link {
      position: absolute;
      top: -100%;
      left: 1rem;
      padding: 0.5rem 1rem;
      background: #6870c4;
      color: #fff;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.8rem;
      border-radius: 0 0 4px 4px;
      z-index: 1000;
      text-decoration: none;
    }
    .skip-link:focus { top: 0; }

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
      background: #6870c4;
      box-shadow: 0 0 4px rgba(104, 112, 196, 0.5);
      flex-shrink: 0;
    }
    .rsrc-toolbar-label {
      font-size: 0.7rem;
      color: #8be9fd;
      letter-spacing: 0.08em;
      flex: 1;
    }
    .rsrc-toolbar-count {
      font-size: 0.72rem;
      color: #5a5f85;
    }
    .rsrc-section-header {
      font-size: 0.7rem;
      color: #5a5f85;
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
      background: rgba(104, 112, 196, 0.1);
      border-left-color: #6870c4;
    }
    #rsrc-sidebar a.rsrc-post-row:focus-visible .rsrc-title { color: #c0c0c0; }
    #rsrc-sidebar a.rsrc-post-row:focus-visible .rsrc-title::before { opacity: 1; }
    #rsrc-sidebar a.rsrc-post-row.active {
      background: rgba(139, 233, 253, 0.05);
      border-left-color: #8be9fd;
    }
    #rsrc-sidebar .rsrc-gutter {
      display: block;
      font-size: 0.68rem;
      color: #5a5f85;
      margin-bottom: 0.1rem;
      width: auto;
    }
    #rsrc-sidebar a.rsrc-post-row.active .rsrc-gutter { color: #6870c4; }
    #rsrc-sidebar .rsrc-title {
      display: block;
      font-family: system-ui, -apple-system, "Segoe UI", "Roboto", sans-serif;
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
      color: #8be9fd;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.72rem;
      font-weight: normal;
      opacity: 0;
      transition: opacity 0.15s ease;
    }
    #rsrc-sidebar a.rsrc-post-row:hover .rsrc-title::before { opacity: 1; }
    #rsrc-sidebar a.rsrc-post-row.active .rsrc-title { color: #8be9fd; }
    #rsrc-sidebar .rsrc-meta { display: none; }

    /* ── Sidebar: series group affordances ── */
    #rsrc-sidebar .series-header {
      display: block;
      padding: 0.45rem 0.75rem;
      cursor: pointer;
      user-select: none;
      border-left: 2px solid transparent;
      border-bottom: 1px solid #1a1a22;
      transition: background 0.1s, border-color 0.1s;
    }
    #rsrc-sidebar .series-header:hover {
      background: rgba(104, 112, 196, 0.1);
      border-left-color: #6870c4;
    }
    #rsrc-sidebar .series-header:hover .rsrc-title { color: #cdd1e0; }
    #rsrc-sidebar .series-header .rsrc-title-block { display: block; }
    #rsrc-sidebar .series-header .rsrc-meta { display: none; }
    /* je/jne affordance — always visible (overrides the hover-only "call" prefix) */
    #rsrc-sidebar .series-header .rsrc-title::before {
      content: "je   ";
      opacity: 1;
      color: #8be9fd;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.72rem;
      font-weight: normal;
    }
    #rsrc-sidebar .series-group.open > .series-header .rsrc-title::before {
      content: "jne  ";
    }
    #rsrc-sidebar .series-group.open > .series-header { background: rgba(104, 112, 196, 0.06); }
    #rsrc-sidebar .series-children .rsrc-post-row { padding-left: 1.5rem; }

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
      color: #8be9fd;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.85rem;
      text-decoration: none;
    }
    .back-link:hover { text-decoration: underline; }
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
    .toc-trigger:hover { background: rgba(104, 112, 196, 0.1); }
    .toc-label {
      font-size: 0.82rem;
      color: #8be9fd;
      font-weight: 600;
    }
    .toc-toggle {
      color: #6870c4;
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
      color: #8be9fd;
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
      color: #6870c4;
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
      color: #6870c4;
      font-size: 0.72rem;
    }
    .toc-h3 a.toc-active { color: #8be9fd !important; }

    /* ── Article ── */
    article h1 {
      font-size: 1.9rem;
      color: #f0f0f8;
      border-bottom: 1px solid #2a2a3a;
      padding-bottom: 0.5rem;
      margin-bottom: 1.5rem;
    }
    article h2 {
      font-size: 1.2rem;
      color: #8be9fd;
      border-left: 3px solid #6870c4;
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
      border-bottom: 2px solid #6870c4;
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
    article tr:hover td { background: rgba(104, 112, 196, 0.07); }

    /* ── Scroll-to-top ── */
    .scroll-top-btn {
      position: fixed;
      bottom: 1.5rem;
      right: 1.5rem;
      width: auto;
      min-width: 36px;
      height: 36px;
      padding: 0 0.55rem;
      background: rgba(16, 16, 22, 0.9);
      border: 1px solid #2a2a3a;
      border-radius: 4px;
      color: #6870c4;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.72rem;
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
    .scroll-top-btn:hover { color: #8be9fd; border-color: #6870c4; }
    .scroll-top-btn:focus-visible { outline: 2px solid #6870c4; outline-offset: 2px; }
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
      color: #5a5f85;
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
      color: #6870c4;
      padding: 0.55rem 0;
      width: 32px;
      text-align: center;
    }
    #rsrc-sidebar.collapsed .rsrc-toggle-btn:hover { color: #8be9fd; }


    /* ── Mobile nav bar ── */
    #mobile-nav { display: none; }
    #mobile-scrim { display: none; }

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
      article table { display: block; overflow-x: auto; -webkit-overflow-scrolling: touch; max-width: 100%; }
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
        color: #8be9fd;
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
      #mobile-nav .mob-menu {
        background: none;
        border: none;
        color: #6870c4;
        font-size: 1.1rem;
        line-height: 1;
        cursor: pointer;
        padding: 0;
        width: 44px;
        height: 44px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
        margin-right: -0.5rem;
      }
      #mobile-nav .mob-menu:hover,
      #mobile-nav .mob-menu:focus-visible { color: #8be9fd; }
      /* Post-list drawer */
      body.mobile-nav-open { overflow: hidden; }
      body.mobile-nav-open #rsrc-sidebar {
        display: flex;
        position: fixed;
        top: 44px; left: 0; bottom: 0;
        width: 80%;
        max-width: 300px;
        min-width: 0;
        z-index: 150;
        overflow-y: auto;
      }
      body.mobile-nav-open #rsrc-sidebar a.rsrc-post-row,
      body.mobile-nav-open #rsrc-sidebar .series-header { min-height: 44px; }
      body.mobile-nav-open #rsrc-sidebar .rsrc-toggle-btn { display: none; }
      body.mobile-nav-open #mobile-scrim {
        display: block;
        position: fixed;
        top: 44px; left: 0; right: 0; bottom: 0;
        background: rgba(0, 0, 0, 0.55);
        z-index: 140;
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
      font-family: system-ui, -apple-system, "Segoe UI", "Roboto", sans-serif;
      font-size: 0.85rem;
      padding: 0.35rem 0.5rem;
      border-left: 2px solid transparent;
      transition: color 0.12s, border-color 0.12s, background 0.12s;
    }
    .related-post-link:hover {
      color: #8be9fd;
      border-left-color: #6870c4;
      background: rgba(104, 112, 196, 0.08);
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
    .post-pagination-link:focus-visible { text-decoration: underline; }
    .post-pagination-link:focus-visible { outline: 2px solid #6870c4; outline-offset: 3px; }

    /* ── Reading progress bar ── */
    .reading-progress {
      position: fixed;
      top: 0;
      left: 0;
      width: 0%;
      height: 2px;
      background: #6870c4;
      z-index: 999;
      transition: width 0.1s linear;
    }
    @media (max-width: 900px) { .reading-progress { top: 44px; } }

    /* ── Code block titlebar (address + language + copy) ── */
    .pre-wrapper { margin: 1.5rem 0; }
    .pre-wrapper pre { margin: 0; border-radius: 0 0 6px 6px; }
    .pre-wrapper pre code { border-radius: 0 0 6px 6px; }
    .pre-titlebar {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      padding: 0.3rem 0.75rem;
      background: #161620;
      border: 1px solid #2e3050;
      border-bottom: none;
      border-radius: 6px 6px 0 0;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.7rem;
      color: #555872;
      user-select: none;
    }
    .pre-titlebar .pre-addr { letter-spacing: 0.03em; }
    .pre-titlebar .pre-lang { color: #8be9fd; margin-left: auto; text-transform: lowercase; }
    .copy-btn {
      background: transparent;
      border: 1px solid #2e3050;
      color: #8be9fd;
      font-family: "Fira Code", monospace;
      font-size: 0.68rem;
      padding: 0.1rem 0.45rem;
      border-radius: 3px;
      cursor: pointer;
      transition: border-color 0.15s, color 0.15s;
    }
    .copy-btn:hover { border-color: #6870c4; }
    .copy-btn:focus-visible { outline: 2px solid #6870c4; outline-offset: 1px; }
    .copy-btn.copied { color: #50fa7b; border-color: #50fa7b; }

    /* ── Article epilogue ── */
    .post-epilogue {
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px dashed #2a2a3a;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.78rem;
      line-height: 1.8;
      color: #777;
      user-select: none;
    }
    .post-epilogue .ep-i { color: #6870c4; display: inline-block; width: 3.5em; }
    .post-epilogue .ep-o { color: #999; }
    .post-epilogue .ep-c { color: #555872; margin-left: 2em; }
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
  <link rel="stylesheet" href="/css/theme.css" />
</head>
<body>
<!-- .text section is clean. No overlay, no TLS callbacks. Safe to read. -->

<a href="#post-main" class="skip-link">Skip to content</a>

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
    <button class="mob-menu" id="mobMenuBtn" aria-label="Toggle post list" aria-expanded="false" aria-controls="rsrc-sidebar">&#9776;</button>
  </div>
  <div id="mobile-scrim"></div>

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
      related_section="<div class=\"related-posts\"><span class=\"related-label\">; xrefs to this sample &middot; ${tags}</span>${related_html}</div>"
    fi

    cat >> "_site/posts/${slug}.html" << ENDFOOTER
    <div class="post-epilogue" aria-hidden="true">
      <div><span class="ep-i">xor</span><span class="ep-o">eax, eax</span><span class="ep-c">; clean exit</span></div>
      <div><span class="ep-i">ret</span></div>
    </div>
    </article>
    ${related_section}
    <nav class="post-pagination">
      ${prev_html}
      ${next_html}
    </nav>
  </div>

<button class="scroll-top-btn" id="scrollTopBtn" aria-label="Scroll to top" title="ret to 0x0000">^</button>

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

  // ── Series group: toggle + auto-expand active ──
  window.toggleSeries = function(seriesId) {
    var children = document.getElementById("children-" + seriesId);
    var toggle = document.getElementById("toggle-" + seriesId);
    var group = children ? children.parentElement : null;
    if (!children || !toggle) return;
    var isOpen = children.style.display !== "none";
    children.style.display = isOpen ? "none" : "";
    toggle.textContent = isOpen ? "[+]" : "[-]";
    if (group) group.classList.toggle("open", !isOpen);
  };

  if (activeRow) {
    var parentGroup = activeRow.closest(".series-group");
    if (parentGroup) {
      var sid = parentGroup.getAttribute("data-series");
      if (sid) window.toggleSeries(sid);
    }
    setTimeout(function() { activeRow.scrollIntoView({ block: "center", behavior: "instant" }); }, 0);
  }

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

  // ── Mobile post-list drawer ──
  var mobMenuBtn = document.getElementById("mobMenuBtn");
  var mobileScrim = document.getElementById("mobile-scrim");
  function closeMobileNav() {
    document.body.classList.remove("mobile-nav-open");
    if (mobMenuBtn) mobMenuBtn.setAttribute("aria-expanded", "false");
  }
  if (mobMenuBtn) {
    mobMenuBtn.addEventListener("click", function() {
      var open = document.body.classList.toggle("mobile-nav-open");
      mobMenuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }
  if (mobileScrim) {
    mobileScrim.addEventListener("click", closeMobileNav);
  }
  if (sidebar) {
    sidebar.addEventListener("click", function(e) {
      if (e.target.closest("a.rsrc-post-row")) closeMobileNav();
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

  // ── Code block titlebars (address + language) + copy buttons ──
  var codeVA = 0x401000;
  document.querySelectorAll("pre").forEach(function(pre) {
    var wrapper = document.createElement("div");
    wrapper.className = "pre-wrapper";
    pre.parentNode.insertBefore(wrapper, pre);

    var bar = document.createElement("div");
    bar.className = "pre-titlebar";

    var addr = document.createElement("span");
    addr.className = "pre-addr";
    addr.textContent = ".text:" + ("00000000" + codeVA.toString(16).toUpperCase()).slice(-8);
    bar.appendChild(addr);

    var lang = (pre.className || "").split(/\s+/)[0].toLowerCase();
    if (lang === "nosyntax") lang = "";
    var langEl = document.createElement("span");
    langEl.className = "pre-lang";
    langEl.textContent = lang || "data";
    bar.appendChild(langEl);

    // Tell hljs the declared language (it only reads classes on <code>,
    // so without this every block gets auto-detected — often wrongly).
    // Unlabeled blocks are tool output / hexdumps: leave them plain.
    var codeTag = pre.querySelector("code");
    if (codeTag) {
      var hlLang = lang === "vba" ? "vbscript" : lang;
      codeTag.classList.add(hlLang ? "language-" + hlLang : "nohighlight");
    }

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
    bar.appendChild(btn);

    wrapper.appendChild(bar);
    wrapper.appendChild(pre);

    // Next block starts where this one ends, 16-byte aligned
    var codeEl = pre.querySelector("code");
    var len = codeEl ? codeEl.textContent.length : 0;
    codeVA += Math.max(0x10, Math.ceil(len / 16) * 16);
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
        // Live virtual-address readout for the current scroll position
        if (docHeight > 0) {
          var va = Math.min(0xFFFF, Math.round((scrollTop / docHeight) * 0xFFFF));
          scrollBtn.textContent = '0x' + ('0000' + va.toString(16).toUpperCase()).slice(-4);
        }
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

    # ── Emit Jekyll-style permalink redirect stub ──
    # Older URLs of the form /YYYY/MM/DD/slug.html were indexed before the
    # site moved to /posts/slug.html. Generate a physical redirect so Google
    # can consolidate the indexed URL to the current canonical.
    jekyll_year="${date_str:0:4}"
    jekyll_month="${date_str:5:2}"
    jekyll_day="${date_str:8:2}"
    jekyll_dir="_site/${jekyll_year}/${jekyll_month}/${jekyll_day}"
    mkdir -p "$jekyll_dir"
    cat > "${jekyll_dir}/${slug}.html" << ENDREDIRECT
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>${title} — MZHeader</title>
  <link rel="canonical" href="https://mzheader.tech/posts/${slug}.html" />
  <meta name="robots" content="noindex,follow" />
  <meta http-equiv="refresh" content="0; url=https://mzheader.tech/posts/${slug}.html" />
</head>
<body>
  <p>This post has moved to <a href="https://mzheader.tech/posts/${slug}.html">/posts/${slug}.html</a>.</p>
</body>
</html>
ENDREDIRECT
    echo "Redirect: ${jekyll_year}/${jekyll_month}/${jekyll_day}/${slug}.html"
done

# ── Extra rename redirects (old slug → new slug) ──
# The Huntress CTF 2025 post was originally at /2025/11/01/huntress-ctf-2025-...
# before the slug was tightened to huntress-ctf2025.
mkdir -p "_site/2025/11/01"
cat > "_site/2025/11/01/huntress-ctf-2025-reverse-engineering-challenges.html" << 'ENDRENAME'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Huntress CTF 2025 — MZHeader</title>
  <link rel="canonical" href="https://mzheader.tech/posts/huntress-ctf2025-reverse-engineering-challenges.html" />
  <meta name="robots" content="noindex,follow" />
  <meta http-equiv="refresh" content="0; url=https://mzheader.tech/posts/huntress-ctf2025-reverse-engineering-challenges.html" />
</head>
<body>
  <p>This post has moved to <a href="https://mzheader.tech/posts/huntress-ctf2025-reverse-engineering-challenges.html">/posts/huntress-ctf2025-reverse-engineering-challenges.html</a>.</p>
</body>
</html>
ENDRENAME
echo "Redirect: 2025/11/01/huntress-ctf-2025-reverse-engineering-challenges.html"

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
  <meta name="robots" content="index,follow,max-image-preview:large" />
  <meta name="color-scheme" content="dark" />
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
      color: #8be9fd;
      opacity: 0.75;
      letter-spacing: 0.22em;
      text-transform: uppercase;
      margin-bottom: 0.2em;
    }
    .re-char { display: inline-block; }
    .re-char.scrambling { color: #f8f8f2; opacity: 1; }
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
    .pe-window-titlebar .window-title .wt-app { color: #6870c4; }
    .pe-window-titlebar .window-title .wt-sep { color: #333; margin: 0 0.3em; }
    .pe-window-titlebar .window-title .wt-file { color: #c62828; }
    .pe-window-titlebar .window-title .wt-path { color: #666; }
    .pe-window-titlebar .window-spacer { flex: 1; }
    .pe-window-titlebar .window-tag {
      color: #50fa7b;
      opacity: 0.55;
      font-size: 0.72rem;
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
      color: #5a5f85;
    }
    .pe-section-meta span { white-space: nowrap; }
    .pe-section-meta .meta-label { color: #5a5f85; }
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
    .pe-section-divider--text { border-left-color: #6870c4; }
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

    /* .text disasm rows */
    .pe-disasm-row {
      display: flex;
      padding: 0.3rem 1rem;
      line-height: 1.7;
      transition: background 0.1s ease;
    }
    .pe-disasm-row:hover { background: rgba(104, 112, 196, 0.06); }
    .pe-gutter {
      width: 7em;
      flex-shrink: 0;
      color: #5a5a7a;
      font-size: 0.82rem;
      user-select: none;
      padding-top: 0.15em;
    }
    .pe-instr {
      color: #6870c4;
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
      font-family: system-ui, -apple-system, "Segoe UI", "Roboto", sans-serif;
      font-size: 0.95rem;
      line-height: 1.65;
    }
    .pe-operand strong { color: #8be9fd; }
    .pe-operand a { color: #8be9fd !important; transition: color 0.15s ease; }
    .pe-operand a:hover { text-decoration: underline; }
    .pe-comment {
      flex: 1;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.88rem;
      color: #8888b0;
      line-height: 1.65;
    }
    .pe-comment strong { color: #c62828; font-weight: 600; }
    .pe-comment a { color: #8be9fd !important; transition: color 0.15s ease; }
    .pe-comment a:hover { text-decoration: underline; }

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
      background: rgba(104, 112, 196, 0.10);
      border-left-color: #6870c4;
      text-decoration: none;
    }
    .rsrc-post-row:focus-visible .rsrc-gutter { color: #6870c4; }
    .rsrc-post-row:focus-visible .rsrc-title { color: #8be9fd; }
    .rsrc-post-row:focus-visible .rsrc-meta { color: #6e6e90; }
    /* Staggered entrance animation for post rows */
    @keyframes row-enter {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .rsrc-post-row, .series-group {
      animation: row-enter 0.2s ease both;
    }
    @media (prefers-reduced-motion: reduce) {
      .rsrc-post-row, .series-group { animation: none; }
    }


    .rsrc-post-row .rsrc-gutter {
      width: 7em;
      flex-shrink: 0;
      color: #5a5a7a;
      font-size: 0.82rem;
      user-select: none;
      padding-top: 0.15rem;
      transition: color 0.2s ease;
    }
    .rsrc-post-row:hover .rsrc-gutter { color: #6870c4; }
    .rsrc-title-block {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }
    .rsrc-post-row .rsrc-title {
      font-family: system-ui, -apple-system, "Segoe UI", "Roboto", sans-serif;
      font-size: 0.95rem;
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      line-height: 1.5;
    }
    .rsrc-post-row .rsrc-title::before {
      content: "call  ";
      color: #8be9fd;
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
    .rsrc-post-row:hover .rsrc-title { color: #8be9fd; }
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
      font-size: 0.7rem;
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

    /* Social link hover */
    .rsrc-post-row[target="_blank"]:hover .rsrc-title { color: #8be9fd; }
    .rsrc-post-row[target="_blank"]:hover .rsrc-gutter {
      color: #6870c4;
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
      border-color: #5a5f85;
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
    .pe-detail-toolbar .detail-type { color: #5a5f85; }
    .pe-detail-body {
      padding: 0.75rem;
    }
    .pe-detail-title {
      color: #c0c0c0;
      font-family: system-ui, -apple-system, "Segoe UI", "Roboto", sans-serif;
      font-size: 0.92rem;
      font-weight: 500;
      line-height: 1.5;
      margin-bottom: 0.6rem;
    }
    .pe-detail-panel.active .pe-detail-title { color: #8be9fd; }
    .pe-detail-desc {
      color: #666;
      font-family: system-ui, -apple-system, "Segoe UI", "Roboto", sans-serif;
      font-size: 0.82rem;
      line-height: 1.55;
    }
    .pe-detail-panel.active .pe-detail-desc { color: #999; }
    .pe-detail-date {
      margin-top: 0.5rem;
      padding-top: 0.4rem;
      border-top: 1px solid #222233;
      font-size: 0.7rem;
      color: #5a5f85;
    }
    .pe-detail-date .meta-value { color: #50fa7b; }
    .pe-detail-placeholder {
      color: #5a5f85;
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
      font-size: 0.72rem;
      color: #5a5f85;
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
      font-size: 0.7rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      padding: 0.2rem 0.55rem;
      border-radius: 2px;
      cursor: pointer;
      transition: background 0.12s, color 0.12s, border-color 0.12s;
      user-select: none;
    }
    .filter-btn:hover {
      border-color: #6870c4;
      color: #8a8aaa;
    }
    .filter-btn.active {
      background: rgba(104, 112, 196, 0.15);
      border-color: #6870c4;
      color: #8be9fd;
    }
    .filter-count {
      font-size: 0.65rem;
      color: #5a5f85;
      margin-left: 0.15rem;
    }
    .filter-btn.active .filter-count { color: inherit; opacity: 0.7; }
    .filter-btn:focus-visible {
      outline: 2px solid #6870c4;
      outline-offset: 1px;
    }

    /* Skip-to-content link */
    .skip-link {
      position: absolute;
      top: -100%;
      left: 1rem;
      padding: 0.5rem 1rem;
      background: #6870c4;
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
      outline: 2px solid #6870c4;
      outline-offset: -2px;
    }

    /* Series group collapsible styling */
    .series-group { margin: 0; }
    .series-header {
      display: flex;
      align-items: flex-start;
      padding: 0.55rem 1rem;
      line-height: 1.7;
      cursor: pointer;
      user-select: none;
      border-left: 2px solid transparent;
      transition: background 0.12s ease, border-left-color 0.12s ease;
    }
    .series-header:hover {
      background: rgba(104, 112, 196, 0.10);
      border-left-color: #6870c4;
    }
    .series-header:hover .rsrc-gutter { color: #6870c4; }
    .series-header:hover .rsrc-title { color: #8be9fd; }
    .series-header .rsrc-gutter {
      width: 7em;
      flex-shrink: 0;
      color: #5a5a7a;
      font-size: 0.82rem;
      user-select: none;
    }
    .series-header .rsrc-title-block { flex: 1; min-width: 0; }
    .series-toggle { color: #6870c4; }
    .series-label { color: #3a8a4a; }
    .series-header .rsrc-title::before {
      content: "je    ";
      color: #8be9fd;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.82rem;
      font-weight: normal;
      opacity: 0;
      transition: opacity 0.15s ease;
    }
    .series-header:hover .rsrc-title::before { opacity: 1; }
    .series-header:hover .rsrc-gutter { color: #6870c4; }
    .series-group.open .series-header .rsrc-title::before {
      content: "jne   ";
    }
    .series-children {
      margin-left: 2rem;
      border-left: 1px solid rgba(104, 112, 196, 0.35);
    }

    @media (max-width: 600px) {
      html, body { overflow-x: hidden; }
      body { padding: 1rem; }
      .pe-comment { min-width: 0; overflow-wrap: anywhere; }
      .title-malware { font-size: 1.8rem; }
      .title-re { font-size: 0.8rem; letter-spacing: 0.12em; }
      .pe-section-flags { display: none; }
      .pe-gutter { display: none; }
      .rsrc-post-row .rsrc-gutter { display: none; }
      .series-header .rsrc-gutter { display: none; }
      .rsrc-post-row .rsrc-title { white-space: normal; }
      .pe-window-titlebar .wt-path { display: none; }
      .pe-window-titlebar .window-tag { display: none; }
      .about-toggle { font-size: 0.78rem; }
      .rsrc-meta { font-size: 0.8rem; }
      .rsrc-badge { font-size: 0.72rem; opacity: 0.8; }
      .filter-btn { font-size: 0.78rem; padding: 0.32rem 0.7rem; }
    }

    /* Reduced motion preference */
    @media (prefers-reduced-motion: reduce) {
      .title-malware { animation: none !important; }
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
      border-left: 2px solid #6870c4;
    }
    .about-trigger:hover { background: rgba(104, 112, 196, 0.10); }
    .about-trigger:hover .pe-comment::before {
      content: "je    ";
      color: #8be9fd;
      font-size: 0.82rem;
    }
    .about-trigger.open:hover .pe-comment::before {
      content: "jne   ";
    }
    .about-trigger .pe-comment { flex: 1; color: #c0c0e0; cursor: pointer; }
    .about-trigger.open .pe-comment { color: #8be9fd; }
    .about-toggle {
      color: #6870c4;
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
      border-left: 2px solid #6870c4;
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

    /* ── Detail panel hex dump ── */
    .pe-detail-hexdump {
      font-size: 0.62rem;
      line-height: 1.7;
      white-space: pre;
      margin-bottom: 0.6rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid #222233;
      overflow: hidden;
    }
    .pe-detail-hexdump .hd-off { color: #3f4260; margin-right: 0.8em; }
    .pe-detail-hexdump .hd-hex { color: #9da3f0; }
    .pe-detail-hexdump .hd-ascii { color: #8be9fd; opacity: 0.8; margin-left: 0.8em; }

    /* ── DOS stub footer ── */
    .dos-stub {
      max-width: 900px;
      margin: 2.5rem auto 1rem;
      font-family: "Fira Code", "Consolas", monospace;
      font-size: 0.72rem;
      line-height: 1.8;
      color: #555872;
      text-align: center;
      user-select: none;
    }
    .dos-stub .stub-row { white-space: nowrap; overflow: hidden; }
    .dos-stub .stub-off { color: #3f4260; margin-right: 1.2em; }
    .dos-stub .stub-hex { letter-spacing: 0.04em; }
    .dos-stub .stub-hex .mz { color: #6870c4; }
    .dos-stub .stub-ascii { color: #6f7494; margin-left: 1.2em; }
    .dos-stub .stub-ascii .mz { color: #8be9fd; }
    .dos-stub .stub-msg { margin-top: 0.5rem; color: #7c81ac; font-style: italic; }
    @media (max-width: 700px) {
      .dos-stub { font-size: 0.6rem; }
      .dos-stub .stub-ascii { display: none; }
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
  <link rel="stylesheet" href="/css/theme.css" />
</head>
<body>
<!-- Rich header intact. Nothing packed here. -->

<a href="#postsList" class="skip-link">Skip to posts</a>

<header>
  <h1 class="site-title" id="siteTitle"><span class="title-re" id="titleRE">Reverse Engineering</span><span class="title-malware">Malware</span></h1>

  <div class="pe-window">
    <div class="pe-window-titlebar">
      <div class="pe-window-dots">
        <span class="pe-window-dot dot-close"></span>
        <span class="pe-window-dot dot-min"></span>
        <span class="pe-window-dot dot-max"></span>
      </div>
      <span class="window-title"><span class="wt-app">pe-viewer</span><span class="wt-sep">&#8212;</span><span class="wt-path">C:\Samples\</span><span class="wt-file">mzheader</span></span>
      <span class="window-spacer"></span>
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

<footer class="dos-stub" aria-hidden="true">
  <div class="stub-row"><span class="stub-off">0x0000</span><span class="stub-hex"><span class="mz">4D 5A</span> 90 00 03 00 00 00 04 00 00 00 FF FF 00 00</span><span class="stub-ascii"><span class="mz">MZ</span>..............</span></div>
  <div class="stub-row"><span class="stub-off">0x0040</span><span class="stub-hex">0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68</span><span class="stub-ascii">........!..L.!Th</span></div>
  <div class="stub-msg">This program cannot be run in DOS mode.</div>
</footer>

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

  function makeDiv(cls, text) {
    const el = document.createElement('div');
    el.className = cls;
    el.textContent = text;
    return el;
  }
  function makeMetaRow(label, value, extraStyle) {
    const row = document.createElement('div');
    row.className = 'pe-detail-date';
    if (extraStyle) row.setAttribute('style', extraStyle);
    const lbl = document.createElement('span');
    lbl.className = 'meta-label';
    lbl.textContent = label;
    const val = document.createElement('span');
    val.className = 'meta-value';
    val.textContent = value;
    row.appendChild(lbl);
    row.appendChild(document.createTextNode(' '));
    row.appendChild(val);
    return row;
  }
  function hexDump(str) {
    const wrap = document.createElement('div');
    wrap.className = 'pe-detail-hexdump';
    const bytes = [];
    for (let i = 0; i < str.length && bytes.length < 32; i++) {
      const c = str.charCodeAt(i);
      bytes.push(c > 255 ? 0x3f : c);
    }
    for (let row = 0; row < bytes.length; row += 8) {
      const slice = bytes.slice(row, row + 8);
      let hex = slice.map(b => ('0' + b.toString(16).toUpperCase()).slice(-2)).join(' ');
      while (hex.length < 23) hex += ' ';
      const ascii = slice.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
      const line = document.createElement('div');
      const off = makeDiv('hd-off', ('000' + row.toString(16).toUpperCase()).slice(-4));
      off.style.display = 'inline';
      const hx = makeDiv('hd-hex', hex);
      hx.style.display = 'inline';
      const as = makeDiv('hd-ascii', ascii);
      as.style.display = 'inline';
      line.appendChild(off);
      line.appendChild(hx);
      line.appendChild(as);
      wrap.appendChild(line);
    }
    return wrap;
  }
  function showDetail(row) {
    const data = postData[row.id];
    if (data) {
      panel.classList.add('active');
      detailBody.textContent = '';
      detailBody.appendChild(hexDump(data.title));
      detailBody.appendChild(makeDiv('pe-detail-title', data.title));
      detailBody.appendChild(makeDiv('pe-detail-desc', data.desc));
      if (data.series) {
        detailBody.appendChild(makeMetaRow('Posts:', data.count));
      } else {
        detailBody.appendChild(makeMetaRow('TimeDateStamp:', data.date));
        detailBody.appendChild(makeMetaRow('ReadTime:', data.readTime, 'border-top:none;margin-top:0;padding-top:0.2rem;'));
      }
    }
  }
  function hideDetail() { panel.classList.remove('active'); }

  document.querySelectorAll('.rsrc-post-row, .series-header').forEach(row => {
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
      const title = document.getElementById('siteTitle');
      const reSpans = Array.from(reEl.querySelectorAll('.re-char'));
      let scrambleActive = false;
      function scrambleRE() {
        if (!scrambleActive) return;
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
      title.addEventListener('mouseenter', () => {
        if (scrambleActive) return;
        scrambleActive = true;
        scrambleRE();
      });
      title.addEventListener('mouseleave', () => { scrambleActive = false; });
    }
  })();

  // ── Category filter ──
  (function() {
    var filterBar = document.getElementById('filterBar');
    var buttons = filterBar.querySelectorAll('.filter-btn');
    var rows = document.querySelectorAll('#postsList > .rsrc-post-row, #postsList > .series-group');
    var activeCat = 'all';

    // Map badge class suffix to filter category
    function getRowCat(el) {
      var badge = el.querySelector('.rsrc-badge');
      if (!badge) return 'analysis';
      var cls = badge.className;
      var m = cls.match(/rsrc-badge--(\w+)/);
      return m ? m[1] : 'analysis';
    }

    // Series toggle function (global so onclick can reach it)
    window.toggleSeries = function(seriesId) {
      var children = document.getElementById('children-' + seriesId);
      var toggle = document.getElementById('toggle-' + seriesId);
      var group = children ? children.parentElement : null;
      if (!children || !toggle) return;
      var isOpen = children.style.display !== 'none';
      children.style.display = isOpen ? 'none' : '';
      toggle.textContent = isOpen ? '[+]' : '[-]';
      if (group) group.classList.toggle('open', !isOpen);
    };

    var prefersRM = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function applyFilter(cat) {
      activeCat = cat;
      var visibleIdx = 0;
      for (var i = 0; i < rows.length; i++) {
        var el = rows[i];
        var isSeries = el.classList.contains('series-group');
        var elCat = isSeries ? el.getAttribute('data-tag').toLowerCase() : getRowCat(el);
        var show = (cat === 'all' || elCat === cat);
        el.style.display = show ? '' : 'none';
        if (show) {
          if (isSeries) {
            // Update gutter on series header
            var hdrGutter = el.querySelector('.series-header .rsrc-gutter .series-toggle');
            if (!hdrGutter) {
              var g = el.querySelector('.series-header .rsrc-gutter');
              // Series header gutter is the toggle icon, skip offset renumbering
            }
          } else {
            var gutter = el.querySelector('.rsrc-gutter');
            if (gutter) {
              var offset = (visibleIdx * 32).toString(16).toUpperCase();
              while (offset.length < 4) offset = '0' + offset;
              gutter.textContent = '.rsrc:' + offset;
            }
          }
          if (!prefersRM) {
            el.style.animation = 'none';
            el.offsetHeight;
            el.style.animation = '';
            el.style.animationDelay = (visibleIdx * 35) + 'ms';
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
        case "$img_url" in
          /*) img_url="https://mzheader.tech${img_url}" ;;
        esac
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

build_date=$(date -u +%Y-%m-%d)
cat > "_site/sitemap.xml" << ENDSITEMAP
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
  <url>
    <loc>https://mzheader.tech/</loc>
    <lastmod>${build_date}</lastmod>
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
  "theme_color": "#6870c4",
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
  <meta name="robots" content="noindex,follow" />
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
    .instr { color:#6870c4; width:3em; flex-shrink:0; font-size:0.82rem; }
    .operand { color:#e4e4e4; font-size:0.82rem; }
    .comment { color:#8888b0; font-size:0.82rem; }
    .comment strong { color:#c62828; font-weight:600; }
    .sep { color:#2a2a3a; padding:0.1rem 0; font-size:0.78rem; }
    .ret-row { padding:0.6rem 1rem 0.8rem; border-top:1px solid #1e1e28; }
    a { color:#50fa7b; text-decoration:none; font-size:0.82rem; text-shadow:0 0 6px rgba(80,250,123,0.3); transition: text-shadow 0.15s; }
    a:hover { text-shadow:0 0 10px rgba(80,250,123,0.6); }
    a:focus-visible { outline:2px solid #6870c4; outline-offset:2px; }
  </style>
  <link rel="stylesheet" href="/css/theme.css" />
</head>
<body>
<!-- you found the overlay -->
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
        <div class="disasm-row"><span class="gutter">:000D</span><span class="instr">call</span><span class="operand" style="color:#8be9fd">RaiseException</span></div>
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
