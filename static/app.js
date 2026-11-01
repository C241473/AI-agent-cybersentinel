/**
 * CYBERSENTINEL AI — HOLOGRAPHIC HUD COCKPIT LOGIC
 * Implements interactive canvas, synthesized Web Audio FX, and real-time SOC workflows.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Lucide Icons
  if (window.lucide) lucide.createIcons();

  // ==========================================
  // 1. SYNTHESIZED WEB AUDIO FX ENGINE
  // ==========================================
  let soundEnabled = true;
  let audioCtx = null;

  function initAudio() {
    if (!audioCtx) {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) audioCtx = new AudioContext();
    }
    if (audioCtx && audioCtx.state === "suspended") {
      audioCtx.resume();
    }
  }

  function playUiSound(type = "beep") {
    if (!soundEnabled) return;
    try {
      initAudio();
      if (!audioCtx) return;

      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);

      const now = audioCtx.currentTime;

      if (type === "beep") {
        // Futuristic sci-fi UI blip
        osc.type = "sine";
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.exponentialRampToValueAtTime(1760, now + 0.08);
        gain.gain.setValueAtTime(0.04, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
        osc.start(now);
        osc.stop(now + 0.08);
      } else if (type === "action") {
        // Futuristic action confirmation
        osc.type = "triangle";
        osc.frequency.setValueAtTime(440, now);
        osc.frequency.exponentialRampToValueAtTime(880, now + 0.12);
        gain.gain.setValueAtTime(0.06, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
        osc.start(now);
        osc.stop(now + 0.12);
      } else if (type === "alert") {
        // Cyber alert frequency
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(980, now);
        osc.frequency.setValueAtTime(650, now + 0.08);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
        osc.start(now);
        osc.stop(now + 0.2);
      }
    } catch (e) {
      console.warn("Audio FX error:", e);
    }
  }

  const soundToggleBtn = document.getElementById("soundToggleBtn");
  const soundIcon = document.getElementById("soundIcon");
  const soundLabel = document.getElementById("soundLabel");

  if (soundToggleBtn) {
    soundToggleBtn.addEventListener("click", () => {
      soundEnabled = !soundEnabled;
      if (soundEnabled) {
        soundIcon.setAttribute("data-lucide", "volume-2");
        soundLabel.textContent = "AUDIO FX ON";
        playUiSound("beep");
      } else {
        soundIcon.setAttribute("data-lucide", "volume-x");
        soundLabel.textContent = "MUTED";
      }
      if (window.lucide) lucide.createIcons();
    });
  }

  // Live UTC Clock
  const liveUtcClock = document.getElementById("liveUtcClock");
  function updateClock() {
    if (liveUtcClock) {
      const now = new Date();
      liveUtcClock.textContent = now.toUTCString().split(" ")[4] + " UTC";
    }
  }
  setInterval(updateClock, 1000);
  updateClock();

  // ==========================================
  // 2. ANIMATED 3D NEURAL BRAIN CANVAS (Matching image)
  // ==========================================
  const brainCanvas = document.getElementById("neuralBrainCanvas");
  if (brainCanvas) {
    const ctx = brainCanvas.getContext("2d");
    const width = brainCanvas.width;
    const height = brainCanvas.height;

    const numNodes = 28;
    const nodes = [];

    for (let i = 0; i < numNodes; i++) {
      // Shape particles into a stylized brain sphere profile
      const u = Math.random();
      const v = Math.random();
      const theta = u * 2.0 * Math.PI;
      const phi = Math.acos(2.0 * v - 1.0);
      const r = 26 + Math.random() * 8;
      nodes.push({
        x: r * Math.sin(phi) * Math.cos(theta),
        y: r * Math.sin(phi) * Math.sin(theta) * 0.7,
        z: r * Math.cos(phi),
        speed: 0.015 + Math.random() * 0.01
      });
    }

    let angle = 0;
    function drawBrain() {
      ctx.clearRect(0, 0, width, height);
      angle += 0.02;

      const cx = width / 2;
      const cy = height / 2;

      // Projected points
      const proj = nodes.map(n => {
        // Rotate around Y axis
        const cosA = Math.cos(angle);
        const sinA = Math.sin(angle);
        const rx = n.x * cosA - n.z * sinA;
        const rz = n.x * sinA + n.z * cosA;
        const scale = 1.2 + rz / 70;
        return {
          px: cx + rx * scale,
          py: cy + n.y * scale,
          z: rz
        };
      });

      // Draw connecting neural synapses
      ctx.lineWidth = 0.8;
      for (let i = 0; i < proj.length; i++) {
        for (let j = i + 1; j < proj.length; j++) {
          const dx = proj[i].px - proj[j].px;
          const dy = proj[i].py - proj[j].py;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 28) {
            const alpha = Math.max(0, 1 - dist / 28) * 0.55;
            ctx.strokeStyle = `rgba(0, 240, 255, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(proj[i].px, proj[i].py);
            ctx.lineTo(proj[j].px, proj[j].py);
            ctx.stroke();
          }
        }
      }

      // Draw glowing synaptic nodes
      proj.forEach(p => {
        const rad = Math.max(1, (p.z + 40) / 25);
        ctx.fillStyle = "#00f0ff";
        ctx.shadowColor = "#00f0ff";
        ctx.shadowBlur = 6;
        ctx.beginPath();
        ctx.arc(p.px, p.py, rad, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      requestAnimationFrame(drawBrain);
    }
    drawBrain();
  }

  // ==========================================
  // 3. COGNITIVE SPEECH SUBTITLE UPDATER
  // ==========================================
  const avatarSpeechText = document.getElementById("avatarSpeechText");
  function setAvatarVoice(text) {
    if (!avatarSpeechText) return;
    avatarSpeechText.innerHTML = `"${text}"`;
  }

  // Add line to live diagnostic terminal
  const diagnosticLogs = document.getElementById("diagnosticLogs");
  function addDiagLog(logText, isAlert = false) {
    if (!diagnosticLogs) return;
    const div = document.createElement("div");
    div.className = isAlert ? "text-rose-400 font-bold" : "text-cyan-300";
    div.textContent = `> ${logText}`;
    diagnosticLogs.appendChild(div);
    diagnosticLogs.scrollTop = diagnosticLogs.scrollHeight;
    if (diagnosticLogs.children.length > 8) {
      diagnosticLogs.removeChild(diagnosticLogs.children[0]);
    }
  }

  // ==========================================
  // 4. COCKPIT TOOL WORKSPACE SWITCHER
  // ==========================================
  const toolTitles = {
    chat: { title: "AI SOC COPILOT CHAT", icon: "message-square" },
    universal: { title: "UNIVERSAL CYBER INSPECTOR", icon: "scan-eye" },
    logs: { title: "LOG THREAT ANALYZER", icon: "file-search" },
    code: { title: "SAST CODE SECURITY AUDITOR", icon: "shield-alert" },
    network: { title: "NETWORK RECON & HTTP HEADERS", icon: "activity" },
    cve: { title: "CVE THREAT INTELLIGENCE VAULT", icon: "database" },
    report: { title: "EXECUTIVE INCIDENT REPORT", icon: "file-check" }
  };

  window.selectCockpitTool = function(toolName) {
    playUiSound("beep");

    // Update left action buttons
    document.querySelectorAll(".hud-btn-action").forEach(btn => {
      if (btn.getAttribute("data-tool") === toolName) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    });

    // Update title
    const titleEl = document.getElementById("workstationTitle");
    const iconEl = document.getElementById("workstationIcon");
    if (toolTitles[toolName]) {
      if (titleEl) titleEl.textContent = toolTitles[toolName].title;
      if (iconEl) iconEl.setAttribute("data-lucide", toolTitles[toolName].icon);
    }

    // Toggle viewport views
    document.querySelectorAll(".tool-view").forEach(v => {
      v.classList.add("hidden");
    });
    const activeView = document.getElementById(`view-${toolName}`);
    if (activeView) activeView.classList.remove("hidden");

    // Contextual voice prompt
    if (toolName === "chat") {
      setAvatarVoice("Copilot stream ready. Ask me any question or issue a triage directive.");
    } else if (toolName === "universal") {
      setAvatarVoice("Universal Inspector ready. Paste ANY log, code, IP, URL, or query to auto-audit.");
    } else if (toolName === "logs") {
      setAvatarVoice("Log Threat Analyzer loaded. Paste access stream or load the test sample.");
    } else if (toolName === "code") {
      setAvatarVoice("SAST Code Auditor primed. Scan Python or JavaScript for OWASP vulnerabilities.");
    } else if (toolName === "network") {
      setAvatarVoice("Network Recon ready. Scan ports or analyze HTTP security headers.");
    } else if (toolName === "cve") {
      setAvatarVoice("Threat Intel database connected. Query known CVEs and mitigation playbooks.");
    } else if (toolName === "report") {
      setAvatarVoice("Compiling MITRE ATT&CK incident response report...");
      loadCockpitReport();
    }

    addDiagLog(`MODULE_SWITCH: ${toolName.toUpperCase()}`);
    if (window.lucide) lucide.createIcons();
  };

  // Quick prompt trigger
  window.executeQuickPrompt = function(promptText) {
    selectCockpitTool("chat");
    const chatInput = document.getElementById("cockpitChatInput");
    if (chatInput) {
      chatInput.value = promptText;
      const form = document.getElementById("cockpitChatForm");
      if (form) form.dispatchEvent(new Event("submit"));
    }
  };

  // ==========================================
  // 5. TOOL: AI CHAT
  // ==========================================
  const cockpitChatForm = document.getElementById("cockpitChatForm");
  const cockpitChatInput = document.getElementById("cockpitChatInput");
  const chatStream = document.getElementById("chatStream");
  const cockpitSendBtn = document.getElementById("cockpitSendBtn");

  if (cockpitChatForm) {
    cockpitChatForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const message = cockpitChatInput.value.trim();
      if (!message) return;

      playUiSound("action");
      appendChatMessage("user", message);
      cockpitChatInput.value = "";
      cockpitSendBtn.disabled = true;
      cockpitSendBtn.innerHTML = `<span>ANALYZING...</span>`;

      addDiagLog(`QUERY: "${message.substring(0, 24)}..."`);
      setAvatarVoice("Processing neural reasoning loop...");

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message })
        });
        const data = await res.json();

        if (data.error) {
          appendChatMessage("assistant", `⚠️ **Error:** ${data.error}`);
          setAvatarVoice("Triage encountered an unexpected exception.");
        } else {
          appendChatMessage("assistant", data.response);
          setAvatarVoice("Response synthesized. Review findings in the HUD stream.");
          playUiSound("beep");
        }
      } catch (err) {
        appendChatMessage("assistant", `⚠️ **Connection Failure:** ${err.message}`);
        setAvatarVoice("Neural connection lost. Please verify host server.");
      } finally {
        cockpitSendBtn.disabled = false;
        cockpitSendBtn.innerHTML = `<span>SEND</span><i data-lucide="send" class="w-3.5 h-3.5"></i>`;
        if (window.lucide) lucide.createIcons();
      }
    });
  }

  function appendChatMessage(role, content) {
    if (!chatStream) return;
    const msgDiv = document.createElement("div");
    msgDiv.className = `flex gap-2.5 ${role === 'user' ? 'justify-end' : ''}`;

    if (role === "assistant") {
      const renderedHtml = window.marked ? marked.parse(content) : content;
      msgDiv.innerHTML = `
        <div class="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-400/40 text-cyan-300 flex items-center justify-center shrink-0">
          <i data-lucide="shield" class="w-3.5 h-3.5"></i>
        </div>
        <div class="bg-cyber-950/90 border border-cyan-500/30 p-3 rounded-xl text-slate-200 leading-relaxed font-sans text-xs max-w-xl shadow-sm prose prose-invert prose-cyan">
          ${renderedHtml}
        </div>
      `;
    } else {
      msgDiv.innerHTML = `
        <div class="bg-cyan-600/30 border border-cyan-500/50 p-2.5 rounded-xl font-mono text-cyan-200 text-xs max-w-md">
          ${escapeHtml(content)}
        </div>
        <div class="w-7 h-7 rounded-lg bg-cyan-500/30 border border-cyan-500/50 text-cyan-300 flex items-center justify-center shrink-0">
          <i data-lucide="user" class="w-3.5 h-3.5"></i>
        </div>
      `;
    }

    chatStream.appendChild(msgDiv);
    chatStream.scrollTop = chatStream.scrollHeight;
    if (window.lucide) lucide.createIcons();
  }

  // ==========================================
  // 6. TOOL: LOG ANALYZER
  // ==========================================
  const cockpitLoadSampleLog = document.getElementById("cockpitLoadSampleLog");
  const cockpitLogInput = document.getElementById("cockpitLogInput");
  const cockpitLogFile = document.getElementById("cockpitLogFile");
  const cockpitRunLogBtn = document.getElementById("cockpitRunLogBtn");
  const cockpitLogOutput = document.getElementById("cockpitLogOutput");

  if (cockpitLoadSampleLog) {
    cockpitLoadSampleLog.addEventListener("click", async () => {
      playUiSound("action");
      try {
        const res = await fetch("/api/samples/log");
        const data = await res.json();
        if (data.content) {
          cockpitLogInput.value = data.content;
          setAvatarVoice("Sample attack log loaded. Ready for deep threat inspection.");
          addDiagLog("LOAD: sample/access.log");
        }
      } catch (err) {
        alert("Failed to load sample log: " + err.message);
      }
    });
  }

  if (cockpitLogFile) {
    cockpitLogFile.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (!file) return;
      playUiSound("beep");
      const reader = new FileReader();
      reader.onload = (evt) => {
        cockpitLogInput.value = evt.target.result;
        setAvatarVoice(`File "${file.name}" ingested into telemetry stream.`);
        addDiagLog(`INGEST: ${file.name}`);
      };
      reader.readAsText(file);
    });
  }

  if (cockpitRunLogBtn) {
    cockpitRunLogBtn.addEventListener("click", async () => {
      const content = cockpitLogInput.value.trim();
      if (!content) return alert("Please paste or upload log data first.");

      playUiSound("action");
      cockpitRunLogBtn.disabled = true;
      cockpitRunLogBtn.innerHTML = `SCANNING LOG STREAM...`;
      addDiagLog("EXEC: LOG_PARSER_ANALYSIS");
      setAvatarVoice("Scanning log stream for SQLi, XSS, Path Traversal, and Scanners...");

      try {
        const res = await fetch("/api/scan/log", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ log_content: content, target_name: "Web Access Log Stream" })
        });
        const data = await res.json();
        if (data.error) {
          cockpitLogOutput.innerHTML = `<p class="text-rose-400">Error: ${data.error}</p>`;
          return;
        }

        renderCockpitLogResults(data);
        const threats = data.result?.summary?.total_threats_detected || 0;
        if (threats > 0) {
          playUiSound("alert");
          document.getElementById("hudDefcon").textContent = "DEFCON 2 [HIGH]";
          document.getElementById("hudDefcon").className = "px-2 py-0.5 rounded bg-rose-950/80 border border-rose-500/50 text-rose-400 font-bold tracking-wider";
          setAvatarVoice(`⚠️ ALERT: ${threats} hostile attack signatures detected! Containment recommended.`);
          addDiagLog(`CRITICAL: ${threats} threats flagged!`, true);
          const threatCountWidget = document.getElementById("widgetThreatCount");
          if (threatCountWidget) threatCountWidget.textContent = `${threats} DETECTED`;
        } else {
          playUiSound("beep");
          setAvatarVoice("Scan complete: No malicious signatures found. Traffic is nominal.");
          addDiagLog("LOG_SCAN: CLEAN");
        }
      } catch (err) {
        cockpitLogOutput.innerHTML = `<p class="text-rose-400">Scan failed: ${err.message}</p>`;
      } finally {
        cockpitRunLogBtn.disabled = false;
        cockpitRunLogBtn.innerHTML = `<i data-lucide="scan" class="w-4 h-4 mr-2"></i> EXECUTE DEEP LOG THREAT INSPECTION`;
        if (window.lucide) lucide.createIcons();
      }
    });
  }

  function renderCockpitLogResults(data) {
    const result = data.result || {};
    const summary = result.summary || {};
    const attackers = result.top_attacker_ips || [];
    const alerts = result.alerts || [];

    let html = `
      <div class="space-y-3 p-3 rounded-lg bg-cyber-950 border border-cyan-500/30">
        <div class="grid grid-cols-3 gap-2 text-center border-b border-cyan-500/20 pb-2">
          <div>
            <div class="text-[10px] text-slate-400">REQUESTS</div>
            <div class="text-sm font-bold text-white">${summary.total_requests || 0}</div>
          </div>
          <div>
            <div class="text-[10px] text-slate-400">THREATS</div>
            <div class="text-sm font-bold text-rose-400">${summary.total_threats_detected || 0}</div>
          </div>
          <div>
            <div class="text-[10px] text-slate-400">ATTACKERS</div>
            <div class="text-sm font-bold text-amber-400">${summary.unique_attacker_ips || 0}</div>
          </div>
        </div>
    `;

    // Attacker IPs with 1-click copy firewall rule
    if (attackers.length > 0) {
      html += `<div class="space-y-1.5"><div class="text-[11px] font-bold text-rose-300">🚨 HOSTILE IPS & FIREWALL CONTAINMENT:</div>`;
      attackers.forEach(att => {
        html += `
          <div class="p-2 rounded bg-cyber-900 border border-rose-500/30 flex items-center justify-between">
            <div>
              <span class="text-cyan-300 font-bold">${att.ip}</span>
              <span class="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 ml-1">Threat Score: ${att.threat_score}</span>
              <div class="text-[10px] text-slate-400 mt-0.5">${(att.threat_types || []).join(", ")}</div>
            </div>
            <button onclick="copyToClipboard('${att.recommended_action}')" class="px-2 py-1 rounded bg-rose-950 border border-rose-700 hover:bg-rose-900 text-rose-200 text-[10px] transition">
              Copy Drop Rule
            </button>
          </div>
        `;
      });
      html += `</div>`;
    }

    // Top Alerts
    if (alerts.length > 0) {
      html += `<div class="space-y-1"><div class="text-[11px] font-bold text-cyan-300">DETECTED SIGNATURES:</div>`;
      alerts.slice(0, 6).forEach(al => {
        html += `
          <div class="p-1.5 rounded bg-cyber-900/60 text-[10px] flex items-center justify-between border border-cyan-500/20">
            <span class="text-amber-400 font-bold">[${al.threat_type}]</span>
            <span class="text-cyan-300 font-mono">${al.mitre?.technique_id || 'T1190'}</span>
            <span class="text-slate-400 truncate max-w-[140px]">${escapeHtml(al.uri)}</span>
          </div>
        `;
      });
      html += `</div>`;
    }

    html += `</div>`;
    cockpitLogOutput.innerHTML = html;
  }

  // ==========================================
  // 7. TOOL: SAST CODE AUDITOR
  // ==========================================
  const cockpitLoadSampleCode = document.getElementById("cockpitLoadSampleCode");
  const cockpitCodeInput = document.getElementById("cockpitCodeInput");
  const cockpitCodeFile = document.getElementById("cockpitCodeFile");
  const cockpitRunCodeBtn = document.getElementById("cockpitRunCodeBtn");
  const cockpitCodeOutput = document.getElementById("cockpitCodeOutput");

  if (cockpitLoadSampleCode) {
    cockpitLoadSampleCode.addEventListener("click", async () => {
      playUiSound("action");
      try {
        const res = await fetch("/api/samples/code");
        const data = await res.json();
        if (data.content) {
          cockpitCodeInput.value = data.content;
          setAvatarVoice("Vulnerable Python script loaded. Ready for SAST security audit.");
          addDiagLog("LOAD: sample/vulnerable_app.py");
        }
      } catch (err) {
        alert("Failed to load sample code: " + err.message);
      }
    });
  }

  if (cockpitCodeFile) {
    cockpitCodeFile.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (!file) return;
      playUiSound("beep");
      const reader = new FileReader();
      reader.onload = (evt) => {
        cockpitCodeInput.value = evt.target.result;
        setAvatarVoice(`Source code "${file.name}" loaded for SAST inspection.`);
        addDiagLog(`INGEST: ${file.name}`);
      };
      reader.readAsText(file);
    });
  }

  if (cockpitRunCodeBtn) {
    cockpitRunCodeBtn.addEventListener("click", async () => {
      const code = cockpitCodeInput.value.trim();
      if (!code) return alert("Please paste or upload source code first.");

      playUiSound("action");
      cockpitRunCodeBtn.disabled = true;
      cockpitRunCodeBtn.innerHTML = `AUDITING SOURCE CODE...`;
      addDiagLog("EXEC: SAST_SECURITY_AUDIT");
      setAvatarVoice("Auditing code for OWASP Top 10 vulnerabilities and hardcoded secrets...");

      try {
        const res = await fetch("/api/scan/code", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code_content: code, filename: "vulnerable_app.py" })
        });
        const data = await res.json();
        if (data.error) {
          cockpitCodeOutput.innerHTML = `<p class="text-rose-400">Error: ${data.error}</p>`;
          return;
        }

        renderCockpitCodeResults(data);
        const findings = data.result?.findings || [];
        if (findings.length > 0) {
          playUiSound("alert");
          setAvatarVoice(`⚠️ SAST Audit flagged ${findings.length} security flaws! Risk Score: ${data.result.risk_score}/10.`);
          addDiagLog(`SAST_VULNS: ${findings.length} findings`, true);
        } else {
          playUiSound("beep");
          setAvatarVoice("Code audit clean! No hardcoded credentials or critical flaws found.");
          addDiagLog("SAST_AUDIT: CLEAN");
        }
      } catch (err) {
        cockpitCodeOutput.innerHTML = `<p class="text-rose-400">Code audit failed: ${err.message}</p>`;
      } finally {
        cockpitRunCodeBtn.disabled = false;
        cockpitRunCodeBtn.innerHTML = `<i data-lucide="shield-check" class="w-4 h-4 mr-2"></i> RUN SAST STATIC SECURITY AUDIT`;
        if (window.lucide) lucide.createIcons();
      }
    });
  }

  function renderCockpitCodeResults(data) {
    const result = data.result || {};
    const findings = result.findings || [];

    let html = `
      <div class="space-y-2 p-3 rounded-lg bg-cyber-950 border border-purple-500/30">
        <div class="flex justify-between items-center border-b border-purple-500/20 pb-2">
          <span class="text-xs font-bold text-white">Analyzed Lines: ${result.total_lines_analyzed || 0}</span>
          <span class="text-xs font-bold font-mono text-amber-400">Risk Score: ${result.risk_score || 0.0} / 10</span>
        </div>
    `;

    if (findings.length === 0) {
      html += `<p class="text-emerald-400 text-center py-2">✅ Clean Code: No vulnerabilities detected.</p>`;
    } else {
      findings.forEach(f => {
        html += `
          <div class="p-2 rounded bg-cyber-900 border border-purple-500/20 space-y-1">
            <div class="flex justify-between items-center text-[11px]">
              <span class="font-bold text-rose-300">[${f.severity}] ${f.vulnerability}</span>
              <span class="text-purple-300 font-mono">Line ${f.line_number}</span>
            </div>
            <code class="block bg-cyber-950 p-1.5 rounded text-[10px] text-rose-200 overflow-x-auto">${escapeHtml(f.code_snippet)}</code>
            <div class="text-[10px] text-emerald-300">💡 Fix: ${f.remediation}</div>
          </div>
        `;
      });
    }

    html += `</div>`;
    cockpitCodeOutput.innerHTML = html;
  }

  // ==========================================
  // 8. TOOL: NETWORK RECON & HEADERS
  // ==========================================
  const cockpitScanPortBtn = document.getElementById("cockpitScanPortBtn");
  const cockpitHostInput = document.getElementById("cockpitHostInput");
  const cockpitPortOutput = document.getElementById("cockpitPortOutput");

  if (cockpitScanPortBtn) {
    cockpitScanPortBtn.addEventListener("click", async () => {
      const target = cockpitHostInput.value.trim();
      if (!target) return alert("Enter host or IP");
      playUiSound("action");
      cockpitScanPortBtn.disabled = true;
      cockpitPortOutput.innerHTML = `<span class="text-cyan-400">Scanning common ports on ${target}...</span>`;
      addDiagLog(`RECON_PORTS: ${target}`);
      setAvatarVoice(`Reconnaissance initiated against target host ${target}...`);

      try {
        const res = await fetch("/api/scan/network", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type: "ports", target })
        });
        const data = await res.json();
        const openPorts = data.result?.open_ports || [];

        if (openPorts.length === 0) {
          cockpitPortOutput.innerHTML = `<span class="text-emerald-400">🛡️ All tested ports filtered / closed.</span>`;
          setAvatarVoice(`Host ${target} exposes no standard insecure ports.`);
        } else {
          playUiSound("alert");
          let phtml = `<div class="space-y-1">`;
          openPorts.forEach(p => {
            phtml += `<div class="p-1 rounded bg-cyber-900 border border-cyan-500/20 flex justify-between text-[10px]"><span class="text-cyan-300 font-bold">Port ${p.port} (${p.service})</span><span class="text-rose-400 font-bold">${p.risk} RISK</span></div>`;
          });
          phtml += `</div>`;
          cockpitPortOutput.innerHTML = phtml;
          setAvatarVoice(`Identified ${openPorts.length} exposed service ports on target host!`);
        }
      } catch (err) {
        cockpitPortOutput.innerHTML = `<span class="text-rose-400">Scan failed: ${err.message}</span>`;
      } finally {
        cockpitScanPortBtn.disabled = false;
      }
    });
  }

  const cockpitScanHeaderBtn = document.getElementById("cockpitScanHeaderBtn");
  const cockpitUrlInput = document.getElementById("cockpitUrlInput");
  const cockpitHeaderOutput = document.getElementById("cockpitHeaderOutput");

  if (cockpitScanHeaderBtn) {
    cockpitScanHeaderBtn.addEventListener("click", async () => {
      const target = cockpitUrlInput.value.trim();
      if (!target) return alert("Enter URL");
      playUiSound("action");
      cockpitScanHeaderBtn.disabled = true;
      cockpitHeaderOutput.innerHTML = `<span class="text-emerald-400">Inspecting headers for ${target}...</span>`;
      addDiagLog(`RECON_HEADERS: ${target}`);
      setAvatarVoice(`Auditing HTTP security headers for ${target}...`);

      try {
        const res = await fetch("/api/scan/network", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type: "headers", target })
        });
        const data = await res.json();
        const findings = data.result?.findings || [];
        const grade = data.result?.security_grade || "F";

        let hhtml = `<div class="space-y-1"><div class="text-[10px] font-bold text-cyan-300">Grade: ${grade}</div>`;
        findings.forEach(f => {
          hhtml += `<div class="p-1 rounded bg-cyber-900 border border-emerald-500/20 text-[10px] flex justify-between"><span>${f.header}</span><span class="${f.status === 'PASS' ? 'text-emerald-400' : 'text-rose-400'} font-bold">${f.status}</span></div>`;
        });
        hhtml += `</div>`;
        cockpitHeaderOutput.innerHTML = hhtml;
        setAvatarVoice(`Header evaluation complete. Target graded: ${grade}.`);
      } catch (err) {
        cockpitHeaderOutput.innerHTML = `<span class="text-rose-400">Header audit failed: ${err.message}</span>`;
      } finally {
        cockpitScanHeaderBtn.disabled = false;
      }
    });
  }

  // ==========================================
  // 9. TOOL: CVE INTEL VAULT
  // ==========================================
  const cockpitSearchCveBtn = document.getElementById("cockpitSearchCveBtn");
  const cockpitCveInput = document.getElementById("cockpitCveInput");
  const cockpitCveOutput = document.getElementById("cockpitCveOutput");

  window.quickCveLookup = function(cveId) {
    if (cockpitCveInput) {
      cockpitCveInput.value = cveId;
      cockpitSearchCveBtn.click();
    }
  };

  if (cockpitSearchCveBtn) {
    cockpitSearchCveBtn.addEventListener("click", async () => {
      const cveId = cockpitCveInput.value.trim().toUpperCase();
      if (!cveId) return alert("Enter CVE ID");
      playUiSound("action");
      cockpitSearchCveBtn.disabled = true;
      cockpitCveOutput.innerHTML = `<span class="text-amber-400">Querying threat intelligence repository...</span>`;
      addDiagLog(`QUERY_CVE: ${cveId}`);
      setAvatarVoice(`Looking up intelligence advisory for ${cveId}...`);

      try {
        const res = await fetch(`/api/cve/${encodeURIComponent(cveId)}`);
        const data = await res.json();
        const d = data.data || {};

        let cveHtml = `
          <div class="space-y-2">
            <div class="flex justify-between items-center border-b border-cyan-500/20 pb-1.5">
              <span class="font-bold text-white font-orbitron">${data.cve_id}</span>
              <span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold font-mono">CVSS ${d.cvss_score || 'N/A'}</span>
            </div>
            <div class="text-[11px] text-amber-300 font-semibold">${d.name || 'Advisory'}</div>
            <p class="text-[10px] text-slate-300 leading-snug">${d.description || 'No description available.'}</p>
            <div class="p-2 rounded bg-cyber-900 border border-emerald-500/30 text-[10px] space-y-1">
              <div class="font-bold text-emerald-300">Containment Playbook:</div>
              <ul class="list-disc list-inside space-y-0.5 text-slate-300">
                ${(d.mitigation_steps || []).map(s => `<li>${s}</li>`).join("")}
              </ul>
            </div>
          </div>
        `;
        cockpitCveOutput.innerHTML = cveHtml;
        setAvatarVoice(`Advisory details for ${cveId} retrieved.`);
      } catch (err) {
        cockpitCveOutput.innerHTML = `<span class="text-rose-400">CVE query failed: ${err.message}</span>`;
      } finally {
        cockpitSearchCveBtn.disabled = false;
      }
    });
  }

  // ==========================================
  // 10. TOOL: INCIDENT REPORT
  // ==========================================
  const cockpitRefreshReport = document.getElementById("cockpitRefreshReport");
  const cockpitReportPreview = document.getElementById("cockpitReportPreview");

  if (cockpitRefreshReport) {
    cockpitRefreshReport.addEventListener("click", loadCockpitReport);
  }

  async function loadCockpitReport() {
    if (!cockpitReportPreview) return;
    cockpitReportPreview.innerHTML = `<span class="text-cyan-400">Synthesizing incident response report...</span>`;
    addDiagLog("GENERATE: INCIDENT_REPORT");

    try {
      const res = await fetch("/api/report");
      const data = await res.json();
      if (data.report_markdown) {
        cockpitReportPreview.innerHTML = window.marked ? marked.parse(data.report_markdown) : data.report_markdown;
        setAvatarVoice("Incident report compiled successfully.");
      }
    } catch (err) {
      cockpitReportPreview.innerHTML = `<span class="text-rose-400">Report synthesis error: ${err.message}</span>`;
    }
  }

  // ==========================================
  // 5.1 TOOL: UNIVERSAL CYBER INSPECTOR
  // ==========================================
  const universalRunBtn = document.getElementById("universalRunBtn");
  const universalInput = document.getElementById("universalInput");
  const universalOutput = document.getElementById("universalOutput");

  if (universalRunBtn) {
    universalRunBtn.addEventListener("click", async () => {
      const inputData = universalInput.value.trim();
      if (!inputData) return alert("Please paste some data (Log line, Code, IP, URL, or CVE) to inspect.");

      playUiSound("action");
      universalRunBtn.disabled = true;
      universalRunBtn.innerHTML = `<span>ANALYZING &amp; AUTO-AUDITING...</span>`;
      universalOutput.innerHTML = `<span class="text-emerald-400 flex items-center gap-2"><span class="animate-spin inline-block w-3.5 h-3.5 border-2 border-emerald-400 border-t-transparent rounded-full"></span> Identifying input signature and running deep audit...</span>`;

      addDiagLog(`UNIVERSAL_INSPECT: ${inputData.substring(0, 24)}...`);
      setAvatarVoice("Universal Inspector engaged: Auto-detecting input type and executing triage...");

      try {
        const res = await fetch("/api/scan/universal", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input_data: inputData })
        });
        const respData = await res.json();

        if (respData.error) {
          universalOutput.innerHTML = `<p class="text-rose-400">Inspection error: ${respData.error}</p>`;
        } else {
          renderUniversalResults(respData.data);
          playUiSound("beep");
          setAvatarVoice("Universal inspection complete! Detailed telemetry rendered.");
        }
      } catch (err) {
        universalOutput.innerHTML = `<p class="text-rose-400">Connection error: ${err.message}</p>`;
      } finally {
        universalRunBtn.disabled = false;
        universalRunBtn.innerHTML = `<i data-lucide="scan-eye" class="w-4 h-4 mr-2"></i> AUTO-DETECT &amp; INSPECT NOW`;
        if (window.lucide) lucide.createIcons();
      }
    });
  }

  function renderUniversalResults(data) {
    const category = data.category || "GENERAL";
    const badge = data.badge || "INSPECTED";
    const riskScore = data.risk_score || 0.0;
    const synthesis = data.synthesis || "";

    const riskBadgeClass = riskScore >= 7.0 ? 'bg-rose-500/20 text-rose-400 border-rose-800' :
                           riskScore >= 4.0 ? 'bg-amber-500/20 text-amber-400 border-amber-800' : 'bg-emerald-500/20 text-emerald-400 border-emerald-800';

    const renderedMarkdown = window.marked ? marked.parse(synthesis) : synthesis;

    universalOutput.innerHTML = `
      <div class="space-y-2.5 p-3 rounded-lg bg-cyber-950 border border-emerald-500/30">
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-cyan-500/20 pb-2">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded border text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border-cyan-500/40">
              DETECTED: [${badge}]
            </span>
          </div>
          <span class="px-2.5 py-0.5 rounded border text-xs font-mono font-bold ${riskBadgeClass}">
            RISK: ${riskScore} / 10.0
          </span>
        </div>

        <div class="prose prose-invert prose-cyan text-xs leading-relaxed max-w-none">
          ${renderedMarkdown}
        </div>
      </div>
    `;
    if (window.lucide) lucide.createIcons();
  }

  // ==========================================
  // GEMINI API KEY MODAL CONTROLS
  // ==========================================
  const geminiModalBtn = document.getElementById("geminiModalBtn");
  const geminiModal = document.getElementById("geminiModal");
  const closeGeminiModal = document.getElementById("closeGeminiModal");
  const cancelGeminiBtn = document.getElementById("cancelGeminiBtn");
  const saveGeminiKeyBtn = document.getElementById("saveGeminiKeyBtn");
  const geminiKeyInput = document.getElementById("geminiKeyInput");
  const geminiBtnLabel = document.getElementById("geminiBtnLabel");
  const hudEngineMode = document.getElementById("hudEngineMode");
  const hudEngineBadge = document.getElementById("hudEngineBadge");

  function openGeminiModal() {
    playUiSound("action");
    if (geminiModal) geminiModal.classList.remove("hidden");
  }

  function hideGeminiModal() {
    playUiSound("beep");
    if (geminiModal) geminiModal.classList.add("hidden");
  }

  if (geminiModalBtn) geminiModalBtn.addEventListener("click", openGeminiModal);
  if (closeGeminiModal) closeGeminiModal.addEventListener("click", hideGeminiModal);
  if (cancelGeminiBtn) cancelGeminiBtn.addEventListener("click", hideGeminiModal);

  if (saveGeminiKeyBtn) {
    saveGeminiKeyBtn.addEventListener("click", async () => {
      const apiKey = geminiKeyInput.value.trim();
      if (!apiKey) return alert("Please enter your Gemini API Key.");

      saveGeminiKeyBtn.disabled = true;
      saveGeminiKeyBtn.innerHTML = `CONNECTING...`;

      try {
        const res = await fetch("/api/settings/gemini-key", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ api_key: apiKey })
        });
        const data = await res.json();

        if (data.status === "connected") {
          playUiSound("action");
          alert("🎉 Google Gemini AI Connected successfully!");
          hideGeminiModal();
          if (geminiBtnLabel) geminiBtnLabel.textContent = "● GEMINI ACTIVE";
          if (hudEngineMode) hudEngineMode.textContent = "GEMINI 1.5/2.0 ACTIVE";
          if (hudEngineBadge) hudEngineBadge.textContent = "GEMINI PRO";
          setAvatarVoice("Google Gemini Generative AI connected! Ready for deep multi-modal reasoning.");
          addDiagLog("AI_LINK: GEMINI_CONNECTED");
        } else {
          alert("Failed to connect: " + (data.error || "Unknown error"));
        }
      } catch (err) {
        alert("Error connecting Gemini API: " + err.message);
      } finally {
        saveGeminiKeyBtn.disabled = false;
        saveGeminiKeyBtn.innerHTML = `CONNECT &amp; ACTIVATE`;
      }
    });
  }

  // Check initial status on load
  async function checkInitStatus() {
    try {
      const res = await fetch("/api/status");
      const d = await res.json();
      if (d.has_gemini_key) {
        if (geminiBtnLabel) geminiBtnLabel.textContent = "● GEMINI ACTIVE";
        if (hudEngineMode) hudEngineMode.textContent = "GEMINI 1.5/2.0 ACTIVE";
        if (hudEngineBadge) hudEngineBadge.textContent = "GEMINI PRO";
      }
    } catch (e) {}
  }
  checkInitStatus();

  // Session Reset
  const resetSessionBtn = document.getElementById("resetSessionBtn");
  if (resetSessionBtn) {
    resetSessionBtn.addEventListener("click", async () => {
      if (!confirm("Reset all telemetry and conversation context?")) return;
      playUiSound("action");
      try {
        await fetch("/api/chat/clear", { method: "POST" });
        setAvatarVoice("All incident telemetry and memory cleared. Ready for new operations.");
        addDiagLog("SYS_RESET: SUCCESS");
        if (chatStream) {
          chatStream.innerHTML = `
            <div class="flex gap-2.5">
              <div class="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-400/40 text-cyan-300 flex items-center justify-center shrink-0">
                <i data-lucide="shield" class="w-3.5 h-3.5"></i>
              </div>
              <div class="bg-cyber-950/90 border border-cyan-500/30 p-3 rounded-xl text-slate-200 leading-relaxed font-sans text-xs">
                <p class="font-orbitron font-bold text-cyan-400 text-xs mb-1">CYBERSENTINEL // ASSISTANT ENGAGED</p>
                <p>System memory cleared. Ready to protect your systems.</p>
              </div>
            </div>
          `;
          if (window.lucide) lucide.createIcons();
        }
      } catch (err) {
        alert("Reset failed: " + err.message);
      }
    });
  }

  // Global Clipboard Helper
  window.copyToClipboard = function(text) {
    playUiSound("action");
    navigator.clipboard.writeText(text).then(() => {
      setAvatarVoice("Firewall containment rule copied to your clipboard!");
      addDiagLog(`COPY_RULE: ${text.substring(0, 20)}...`);
      alert("Copied to clipboard: " + text);
    }).catch(err => {
      alert("Copy failed: " + err);
    });
  };

  // Helper Escape HTML
  function escapeHtml(string) {
    if (!string) return '';
    return String(string)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
