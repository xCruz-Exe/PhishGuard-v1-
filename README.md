# PhishGuard v1 🛡️

PhishGuard is a high-performance, next-generation phishing detection web application. It leverages a custom heuristic engine combined with the VirusTotal API to identify malicious URLs and protect users from cyber threats in real-time.

> [!NOTE]
> **A Note from the Developer (Cruz):**
> This project was built primarily as a learning journey. I don't claim to be an expert in cyber security or advanced web development yet, but I created this to explore how heuristic engines and security APIs work. I'm constantly learning and would love to hear any feedback or suggestions to improve this project!

![PhishGuard Preview](https://via.placeholder.com/1200x600/070b14/6366f1?text=PhishGuard+v1+Analysis+Dashboard)

## ✨ Features

- **Dual-Engine Analysis**: Combines local heuristic pattern recognition with global threat intelligence via VirusTotal.
- **Real-Time Scanning**: Interactive scanning process with live progress feedback.
- **Risk Intensity Meter**: Visual gauge showing the calculated risk percentage of any URL.
- **Domain DNA**: Deep analysis of domain metadata, TLD risk, and potential typosquatting/impersonation.
- **Scan History**: Locally persisted history of recent scans using browser storage.
- **Premium UI/UX**: Modern glassmorphism design with smooth Framer Motion animations.
- **Live Threat Feed**: Simulated live intelligence feed for proactive awareness.

## 🚀 Tech Stack

- **Frontend**: React.js
- **Styling**: Vanilla CSS (Modern Design System)
- **Animations**: Framer Motion
- **Icons**: Lucide React
- **Build Tool**: Vite
- **API**: VirusTotal v3 API

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/phishguard-v1.git
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Add your VirusTotal API Key:
   Open `src/App.jsx` and add your key to the `VT_API_KEY` variable:
   ```javascript
   const VT_API_KEY = 'YOUR_API_KEY_HERE';
   ```

4. Run the development server:
   ```bash
   npm run dev
   ```

## 🛡️ Heuristic Analysis Logic

The internal engine checks for several risk factors including:
- **IP-based Hostnames**: High-risk indicator.
- **Suspicious TLDs**: Detects `.xyz`, `.top`, `.ga`, etc.
- **Deceptive Keywords**: Identifies terms like `verify`, `secure-login`, `wallet`.
- **Brand Impersonation**: Uses regex to catch typosquatted domains (e.g., `g00gle`, `faceb0ok`).
- **URL Complexity**: Analyzes length and subdomain depth.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---
Developed with ❤️ by **Cruz** from **Team Thinking**
