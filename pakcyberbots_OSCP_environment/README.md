# PakCyberbot's OSCP Environment

A powerful and fully automated OSCP-style penetration testing environment initializer by **PakCyberbot**. This script helps you set up multi-terminal layouts, define per-project environments, start HTTP servers, generate Markdown reports, and much more.

---

## 📦 Features

* **Multi-Terminal Setup:**

  * Instantly launch preconfigured terminal layouts for different pentest scenarios.
  * Includes a dedicated OSCP exam-style 6-terminal layout with environment variables.

* **Markdown → PDF Reporting:**

  * Use `md2pdf_reportgen` to convert Obsidian markdown to clean, professional PDF reports.
  * Automatically formats images with captions, borders, and page consistency.

* **Session Logging:**

  * Use `toggle-terminal-logging` to enable/disable terminal session logging.
  * Even logs reverse shells — perfect for documentation and reporting.

* **Smart HTTP Server:**

  * `fuzzy-httpserver` launches an enhanced HTTP file server.
  * Auto-corrects URL typos, supports uploads, and includes many common pentest tools.

* **BloodHound Setup:**

  * Use `bloodhound-docker start/stop` to quickly deploy BloodHound with Docker. **Docker is required, it should be installed in your system before installing this environment**

* **Obsidian Template Integration:**

  * Markdown templates are compatible with Obsidian + Templater plugin.
  * Auto IP assignment and reusable blocks for structured reporting.

---

## 🚀 Usage

```bash
chmod +x OSCP_envsetup.sh
./OSCP_envsetup.sh
```

Once installed, the following commands will be globally available:

| Command                        | Description                                   |
| ------------------------------ | --------------------------------------------- |
| `setup_pentest_env`            | Launch terminal layout with environment setup |
| `md2pdf_reportgen`             | Convert Obsidian Markdown to styled PDF       |
| `toggle-terminal-logging`      | Enable/disable terminal session logging       |
| [`fuzzy-httpserver`](https://pypi.org/project/fuzzy-httpserver/)             | Start smart HTTP file server   |
| `bloodhound-docker start/stop` | Manage BloodHound via Docker                  |

![Video](assets/installation.mov)

---

## 🖥️ Terminator Keyboard Shortcuts

| Shortcut         | Action                       |
| ---------------- | ---------------------------- |
| Ctrl + Shift + L | Vertical split terminal      |
| Ctrl + Shift + J | Horizontal split terminal    |
| Ctrl + Tab       | Switch between terminals     |
| Ctrl + N         | Switch to white theme        |
| Ctrl + Shift + Z | Zoom in/out focused terminal |
| Ctrl + Shift + W | Close current terminal       |

---

## 📝 Markdown Templates for Obsidian

* Markdown templates are included to help you write:

  * Note Taking During Challenges/Exam
  * Final OSCP report

* Supports the Obsidian Templater plugin for dynamic content like:

  * Inserting IP addresses
  * Timestamping
  * Auto-generating structure

I will share a fully configured Obsidian Vault soon!

---

## 📣 Support & Contribution

If this helped you, feel free to:

* ⭐ Star the repo
* 🐞 Report bugs
* 🧠 Suggest new features
* ☕ [Buy Me a Coffee](https://buymeacoffee.com/pakcyberbot) to support me for future Content

---

## 🧑‍💻 Author

- GitHub: [@PakCyberbot](https://github.com/PakCyberbot)
- YouTube: [@PakCyberbot](https://youtube.com/@PakCyberbot)
- Twitter (X): [@PakCyberbot](https://x.com/PakCyberbot)
- LinkedIn: [@PakCyberbot](https://linkedin.com/in/PakCyberbot)
- Instagram: [@PakCyberbot](https://instagram.com/PakCyberbot)
- Facebook: [@PakCyberbot](https://facebook.com/PakCyberbot)
- Medium: [@PakCyberbot](https://medium.com/@pakcyberbot)

🔗 **Follow on your favorite platform** for updates, demos, and tutorials, as well as more informative material and future content drops.


