<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Reverse Engineering Malware</title>

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
  <h1>Reverse Engineering Malware</h1>
    <pre style="font-family: monospace; color: #ff79c6; text-align: center;">
 __  __ ______ 
|  \/  |___  /
| |\/| |  / / 
| |  | | / /__
|_|  |_|/____|
 MZ HEADER
</pre>
  <p>
    Showcasing practical malware analysis techniques, tips, and tricks across diverse samples — covering topics like deobfuscation, debugging, disassembly, and more
  </p>
  <p>
    The tools I rely on are all freely available — with most included out-of-the-box in <strong>FLARE VM</strong>
  </p>
  <p>
    All malware samples can be found on 
    <a class="normal-link" href="https://www.virustotal.com/" target="_blank">VirusTotal</a> /
    <a class="normal-link" href="https://bazaar.abuse.ch/" target="_blank">MalwareBazaar</a>.
  </p>
</header>


</body>
</html>
