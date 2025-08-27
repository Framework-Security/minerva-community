<!-- PROJECT LOGO -->
<link href="https://fonts.googleapis.com/css2?family=Lato&display=swap" rel="stylesheet">
<p align="center">
  <a href="https://www.frameworksecurity.com" target="_blank">
    <img src="static/fws_logo.png" alt="Project Logo" height="220">
  </a>
</p>

<!-- PROJECT TITLE -->
<h1 align="center" style="font-family:Lato;">
  <b>Minerva Insights</b>
</h1>

<p align="center" style="font-family:Lato;">
  The reporting solution for security professionals.  
  <br />
  <a href="https://www.frameworksecurity.com"><strong>Visit Framework Security »</strong></a>
  <br />
  <br />
  <a href="https://github.com/Framework-Security/minerva-community/issues">Report Bug</a>
  ·
  <a href="https://github.com/Framework-Security/minerva-community/issues">Request Feature</a>
</p>

---

<p style="font-family:Lato;">
Minerva Insights is a web-based, open-source reporting platform designed for security professionals. Instead of starting from scratch for every engagement, pentesters can build and maintain a finding database specific to each client. 

Every finding includes:
</p>

- Technical description
- Business impact
- Remediation guidance
- References (CVE, CWE, OWASP, etc.)

---

## Running Minerva Insights

<p style="font-family:Lato;"> Minerva is built on top of the wkhtmltopdf document rendering engine, and requires a version that has been patched with QtWebKit. That can be found on the <a href="https://github.com/wkhtmltopdf/packaging/releases">wkhtmltopdf github.</a><br><br>Once installed, use `pip install -r requirements.txt` to install the needed dependencies.<br><br>From there, PDF's can begin being generated. Modify the generate.py file to insert your custom content, including your own toolkits and vulnerabilities!<br><br><br>If you have any questions or inquiries, feel free to <a href="https://www.frameworksecurity.com">reach out</a>, <a href="https://github.com/Framework-Security/minerva-community/issues">open an issue</a> or create a pull request.</p>

