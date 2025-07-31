# Malware Scanner
![made-with-python][made-with-python]
![Python Versions][pyversion-button]

[pyversion-button]: https://img.shields.io/pypi/pyversions/Markdown.svg
[made-with-python]: https://img.shields.io/badge/Made%20with-Python-1f425f.svg

- Very basic malware Scanner by hash comparison
- Sometimes this can be needed when an incident response.
- If you found new or suspicious files when you do response, you want to check out where these files exist in systems. so then you may need like this tool. this is a demo version. not complete. you have to change and modify code and make it yours.
- Let me know if there are any changes required or additional features need it.
- and press the "stars" if it helps. then it will continue to improvement.

# Features
- File inspection based on hash (free malware hashes)
- Scanning include subdirectories
- Multithreading Jobs
- Define file extensions to scan
- Define directories not to scan
- Easy to attach scan_logs to the SIEM (e.g Splunk)
- Easy to Handle and changeable code/function structure (if you interest)

## Preview
<img src=./preview.png>


## Scan result_log
- datetime, scan_id, os, hostname, ip, file.........hash,
```
datetime="2025-03-29 16:55:44",scan_id="da3b8d8f-7dd3-4cab-9be6-6fa05a5d4bb1",os="Windows",hostname="Windows-786",ip="192.168.73.208",infected_file="C:\Users\Admin\Pictures\Saved Pictures\b8f21f17e79ca095fce11156b02bf6611abaf18b4bdf298ffffa42b8d7cbec57.xapk",sha256="b8f21f17e79ca095fce11156b02bf6611abaf18b4bdf298ffffa42b8d7cbec57",created_at="2025-03-29 16:42:36",modified_at="2025-03-29 11:06:16"
datetime="2025-03-29 16:55:59",scan_id="ec5d7ce5-2d05-41e2-9b20-ec648c405383",os="Windows",hostname="Windows-786",ip="192.168.73.208",infected_file="C:\Users\Admin\Pictures\Saved Pictures\b8f21f17e79ca095fce11156b02bf6611abaf18b4bdf298ffffa42b8d7cbec57.xapk",sha256="b8f21f17e79ca095fce11156b02bf6611abaf18b4bdf298ffffa42b8d7cbec57",created_at="2025-03-29 16:42:36",modified_at="2025-03-29 11:06:16"
datetime="2025-03-29 16:56:22",scan_id="6d5b5f12-684d-45a1-86e1-8ebe721645ac",os="Windows",hostname="Windows-786",ip="192.168.73.208",infected_file="C:\Users\Admin\Pictures\Saved Pictures\b8f21f17e79ca095fce11156b02bf6611abaf18b4bdf298ffffa42b8d7cbec57.xapk",sha256="b8f21f17e79ca095fce11156b02bf6611abaf18b4bdf298ffffa42b8d7cbec57",created_at="2025-03-29 16:42:36",modified_at="2025-03-29 11:06:16"


```

