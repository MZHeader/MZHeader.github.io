<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Malware Analysis & DFIR</title>

  <!-- Dracula syntax highlighting -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/base16/dracula.min.css">

  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script>hljs.highlightAll();</script>

  <style>
    body {
      background: #1e1e1e;
      color: #dcdcdc;
      font-family: 'Segoe UI', 'Roboto', sans-serif;
      padding: 2rem;
      line-height: 1.6;
    }
    h1, h2 {
      color: #ff79c6;
    }
    header {
      border-bottom: 1px solid #333;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
    }
    header p {
      color: #bbbbbb;
      max-width: 70ch;
    }
    a {
      color: #ff79c6;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
      color: #50fa7b;
    }
    .post-list {
      list-style: none;
      padding: 0;
    }
    .post-list li {
      margin-bottom: 1rem;
    }
    .post-list .post-date {
      color: #888;
      margin-right: 0.5rem;
      font-size: 0.9rem;
    }
    pre code {
      display: block;
      padding: 1em;
      background: #2d2d2d;
      color: #f8f8f2;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.95rem;
      font-family: 'Fira Code', 'Consolas', monospace;
      box-shadow: 0 0 8px #00000080;
      border: 1px solid #444;
    }
    section {
      margin-bottom: 2rem;
    }
  </style>
</head>
<body>

  <header>
    <h1>Malware Analysis & DFIR Tips</h1>
    <p>
      Showcasing malware analysis techniques on various samples, plus general DFIR tips & tricks to aid investigations.
    </p>
    <p>
      The tools I use are freely available — most come pre-installed with <strong>FLARE VM</strong>.
    </p>
    <p>
      All samples are available on 
      <a href="https://www.virustotal.com/" target="_blank" style="color:#8be9fd;">VirusTotal</a> /
      <a href="https://bazaar.abuse.ch/" target="_blank" style="color:#8be9fd;">MalwareBazaar</a>.
    </p>
  </header>

  <section>
    <h2>Example Python Snippet</h2>
    <pre><code class="language-python">
octal_values = [70, 62, 64, 60, 61]
ascii_chars_from_octal = ''.join([chr(int(str(num), 8)) for num in octal_values])
print(ascii_chars_from_octal)
    </code></pre>
  </section>

  <section>
    <h2>Posts</h2>
    <ul class="post-list">
      {% for post in site.posts %}
      <li>
        <span class="post-date">{{ post.date | date: "%b %-d, %Y" }}</span>
        <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
      </li>
      {% endfor %}
    </ul>
  </section>

</body>
</html>
