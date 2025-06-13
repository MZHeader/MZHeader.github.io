<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Malware Analysis & DFIR</title>

  <!-- Dracula syntax highlighting -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/base16/dracula.min.css">
  
  <!-- Custom dark theme + layout -->
  <link rel="stylesheet" href="main.css">

  <!-- highlight.js -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script>hljs.highlightAll();</script>

  <!-- Google Analytics -->
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-48M02RY99Q"></script>
  <script>
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', 'G-48M02RY99Q');
  </script>
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
      <a href="https://www.virustotal.com/" target="_blank">VirusTotal</a> /
      <a href="https://bazaar.abuse.ch/" target="_blank">MalwareBazaar</a>.
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

</body>
</html>
