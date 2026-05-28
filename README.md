# SY0-701 Security Header Analyzer

A full-stack, production-ready educational tool that performs deep inspection of any website's HTTP security headers. Designed for cybersecurity students and practitioners preparing for the **CompTIA Security+ SY0-701 Exam**, this application helps clarify web architecture security concepts, browser-based attacks, and secure server configurations.

---

## 🚀 Project Features

- **Deep Header Inspection**: Analyzes the presence and strength of 8 critical security headers.
- **Weighted Security Score**: Calculates an overall rating (0–100) with a corresponding letter grade (A/B/C/D/F).
- **Educational Explanations**: Provides beginner-friendly definitions, intermediate impact statements, real-world attack scenarios (Clickjacking, MITM, MIME-sniffing), and CompTIA Security+ SY0-701 Exam Tips for each header.
- **Recommendations & Quick Fixes**: Generates server-specific config recommendations (e.g. Nginx directives) to resolve issues.
- **Export Reports**: Allows users to download a complete security audit report in structured JSON format.
- **Vibrant Dark-themed UI**: Optimized, fully responsive frontend styled with Tailwind CSS v3.

---

## 📁 Project Structure

```text
security-header-analyzer/
├── backend/
│   ├── main.py          # FastAPI application & API endpoints
│   ├── analyzer.py      # Core header analysis and grading logic
│   └── requirements.txt # Python dependency declaration
└── frontend/
    ├── index.html       # Entrypoint HTML template
    ├── package.json     # Node.js project manifest & scripts
    ├── tailwind.config.js # Tailwind CSS configuration
    ├── postcss.config.js  # PostCSS processor configuration
    ├── vite.config.js   # Vite server settings
    └── src/
        ├── App.jsx      # Main dashboard interface component
        ├── index.css    # Custom styles & Tailwind entry
        └── main.jsx     # React DOM renderer
```

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8 or higher installed on your system.
- Node.js v18 or higher (with npm) installed on your system.

---

### Step 1: Run the Backend (FastAPI)

1. Navigate to the `backend` folder:
   ```bash
   cd backend
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the FastAPI dev server using Uvicorn:
   ```bash
   python main.py
   ```
   *The backend API will run on `http://127.0.0.1:8000`.*

---

### Step 2: Run the Frontend (Vite + React)

1. Open a new terminal window and navigate to the `frontend` folder:
   ```bash
   cd frontend
   ```

2. Install the frontend dependencies:
   ```bash
   npm install
   ```

3. Start the Vite development server:
   ```bash
   npm run dev
   ```
   *The frontend dashboard will run on `http://localhost:5173`.*

---

## 🎓 CompTIA Security+ SY0-701 Learning Objectives

This project implements core security controls mapped directly to the **SY0-701 Exam Objectives**:

1. **Domain 3.0: Secure Network Architecture**
   - **HSTS (Strict-Transport-Security)**: Enforces end-to-end transport layer security. Demonstrates how to block **SSL Stripping / Protocol Downgrade** attacks.
   - **CORS (Access-Control-Allow-Origin)**: Configures boundary controls between origins. Shows how misconfigured wildcards (`*`) can leak data to external scripts.

2. **Domain 4.0: Vulnerabilities & Threats**
   - **X-Frame-Options / CSP frame-ancestors**: Technical mitigations against **Clickjacking**, where transparent layers hijack user input.
   - **Content-Security-Policy (CSP)**: Primary defense-in-depth against **Cross-Site Scripting (XSS)** (Reflected, Stored, DOM-based) by limiting script source origins.
   - **X-Content-Type-Options**: Mitigation against **MIME-Sniffing** exploitation where media types are executed as code.

---

## 💼 Resume Bullet Points

Add this project to your security/software engineering portfolio with these impact statements:

* "Developed a full-stack **Security Header Analyzer** web application using **FastAPI** (Python) and **React (Vite)** to audit HTTP server response headers for secure architecture alignment."
* "Implemented automated heuristic analysis for **Content-Security-Policy (CSP)**, identifying wildcards, insecure HTTP sources, and `'unsafe-inline'` directives to prevent Cross-Site Scripting (XSS)."
* "Created a detailed security grading system that assesses web protocol configuration rules mapped to **CompTIA Security+ SY0-701** guidelines, calculating a weighted security posture score (0-100)."
* "Configured cross-origin controls by integrating **CORS middleware** between FastAPI and Vite dev server, demonstrating correct origin limitation parameters."
* "Generated actionable fix recommendations (e.g. Nginx config blocks) for missing or weak headers, enabling rapid security remediation for web applications."
