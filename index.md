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
      color: #5625be;
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
      color: #5625be;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
      color: #50fa7b;
    }
    .normal-link {
      color: #8be9fd !important;
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
    Demonstrating malware analysis techniques on a variety of samples, along with practical DFIR tips and tricks to support investigations.
  </p>
  <p>
    The tools I rely on are all freely available — with most included out-of-the-box in <strong>FLARE VM</strong>.
  </p>
  <p>
    All malware samples can be found on 
    <a class="normal-link" href="https://www.virustotal.com/" target="_blank">VirusTotal</a> /
    <a class="normal-link" href="https://bazaar.abuse.ch/" target="_blank">MalwareBazaar</a>.
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

<section class="posts">
  <h2>Posts</h2>

  <style>
    .posts h2 {
      color: #50fa7b; /* Posts section header: green */
      margin-bottom: 1rem;
    }

    .post-list {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    .post-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background-color: #262626;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      box-shadow: 0 0 5px rgba(0,0,0,0.4);
      transition: background 0.3s ease;
    }

    .post-item:hover {
      background-color: #2f2f2f;
    }

    .post-date {
      font-size: 0.9rem;
      color: #aaaaaa;
      min-width: 110px;
    }

    .post-title a {
      color: #50fa7b; /* Post titles: green */
      font-weight: 500;
      text-decoration: none;
    }

    .post-title a:hover {
      text-decoration: underline;
      color: #7fffb7; /* Slightly brighter green on hover */
    }

    /* Site main title in header remains white: optional override for clarity */
    header h1 {
      color: #ffffff;
    }
  </style>

  <div class="post-list">
    {% for post in site.posts %}
      <div class="post-item">
        <div class="post-date">{{ post.date | date: "%b %-d, %Y" }}</div>
        <div class="post-title">
          <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
        </div>
      </div>
    {% endfor %}
  </div>
</section>




</body>
</html>
