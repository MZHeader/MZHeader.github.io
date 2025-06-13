---
layout: default
---

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
  <h2>Posts</h2>
  <ul class="post-list">
    {% for post in site.posts %}
      <li>
        <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
        <span class="post-date">{{ post.date | date: "%b %-d, %Y" }}</span>
      </li>
    {% endfor %}
  </ul>
</section>
