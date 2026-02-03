(() => {
  "use strict";

  const MODEL = window.SAFESCAN_MODEL;
  if (!MODEL || !MODEL.vectorizer || !MODEL.model) {
    // Fail loudly so it's obvious in WebView / browser console.
    throw new Error("SafeScan model data missing (model.js not loaded).");
  }

  const MAX_HISTORY = 12;
  const MAX_URLS = 10;
  const MAX_ANALYSIS_CHARS = 8000;
  const MAX_HISTORY_SNIPPET_CHARS = 180;
  const STORAGE_LANG_KEY = "safescan_lang";
  const STORAGE_HISTORY_KEY = "safescan_history";

  const TRANSLATIONS = {
    en: {
      title: "SafeScan Offline",
      brand: "SafeScan",
      tagline: "Phishing & scam detection (offline)",
      hero_title: "Detect suspicious links and messages in seconds.",
      hero_text:
        "Paste a URL, text, or a full email. SafeScan runs URL heuristics and an on-device ML model.",
      badge_1: "URL heuristics",
      badge_2: "On-device ML",
      badge_3: "Confidence meter",
      example_label: "Example",
      example_text: "secure-login-paypal.com",
      feature_1_title: "URL checks",
      feature_1_text: "Flags suspicious domains, subdomains, and phishing patterns.",
      feature_2_title: "Text scanning",
      feature_2_text: "Classifies messages as safe or unsafe using the embedded model.",
      feature_3_title: "Clear results",
      feature_3_text: "Readable explanations with a simple risk signal.",
      scan_title: "Scan now",
      scan_subtitle: "Paste a URL, message, or a full email to analyse.",
      placeholder: "Enter text or URL...",
      check: "Check",
      privacy_note: "Runs locally on your device. No data is sent anywhere.",
      confidence: "Confidence",
      safe: "Safe",
      unsafe: "Unsafe",
      url: "URL",
      urls: "URLs",
      text: "Text",
      email: "Email",
      you: "You",
      history_title: "History",
      history_empty: "No scans yet. Your previous checks will appear here.",
      history_note: "History is stored on this device.",
      clear_history: "Clear",
      text_analysis_title: "Text analysis",
      url_checks_title: "URL checks",
      urls_none: "No URLs detected in this input.",
      ml_safe_msg: "No obvious red flags were detected in the text.",
      ml_unsafe_msg: "This text looks suspicious and may be phishing or a scam.",
      install: "Install",
      toggle: "العربية",
      footer: "Educational project • Always verify before you click."
    },
    ar: {
      title: "SafeScan (غير متصل)",
      brand: "SafeScan",
      tagline: "كشف التصيّد والاحتيال (بدون إنترنت)",
      hero_title: "اكشف الروابط والرسائل المشبوهة خلال ثوانٍ.",
      hero_text:
        "الصق رابطًا أو نصًا أو بريدًا كاملًا. يقوم SafeScan بفحص الروابط وتشغيل نموذج تعلم آلي على جهازك.",
      badge_1: "فحص الروابط",
      badge_2: "نموذج على الجهاز",
      badge_3: "مؤشر الثقة",
      example_label: "مثال",
      example_text: "secure-login-paypal.com",
      feature_1_title: "فحص الروابط",
      feature_1_text: "يرصد النطاقات والكلمات والأنماط الشائعة في التصيّد.",
      feature_2_title: "تحليل الرسائل",
      feature_2_text: "يصنّف الرسائل إلى آمنة أو غير آمنة باستخدام النموذج المضمّن.",
      feature_3_title: "نتيجة واضحة",
      feature_3_text: "شرح مبسّط مع إشارة واضحة للمخاطر.",
      scan_title: "تحقق الآن",
      scan_subtitle: "الصق رابطًا أو رسالة أو بريدًا كاملًا للتحليل.",
      placeholder: "اكتب رسالة أو رابط...",
      check: "تحقق",
      privacy_note: "يعمل على جهازك فقط. لا يتم إرسال أي بيانات.",
      confidence: "مستوى الثقة",
      safe: "آمن",
      unsafe: "غير آمن",
      url: "رابط",
      urls: "الروابط",
      text: "نص",
      email: "بريد",
      you: "أنت",
      history_title: "السجل",
      history_empty: "لا يوجد سجل بعد. ستظهر نتائج التحقق السابقة هنا.",
      history_note: "يتم حفظ السجل على هذا الجهاز.",
      clear_history: "مسح",
      text_analysis_title: "تحليل النص",
      url_checks_title: "فحص الروابط",
      urls_none: "لم يتم العثور على روابط في هذا النص.",
      ml_safe_msg: "لم يتم رصد مؤشرات واضحة على الخطر في النص.",
      ml_unsafe_msg: "يبدو هذا النص مشبوهًا وقد يكون تصيّدًا أو احتيالًا.",
      install: "تثبيت",
      toggle: "English",
      footer: "مشروع تعليمي • تحقّق دائمًا قبل الضغط على أي رابط."
    }
  };

  const URL_MESSAGES_AR = {
    "Invalid URL format": "صيغة الرابط غير صحيحة",
    "Suspicious keyword found in domain": "تم العثور على كلمة مشبوهة في النطاق",
    "Too many subdomains": "يوجد عدد كبير من النطاقات الفرعية",
    "URL looks safe": "يبدو الرابط آمنًا"
  };

  const SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "free",
    "bonus",
    "click",
    "bank"
  ];

  function round2(n) {
    return Math.round(n * 100) / 100;
  }

  function nowStamp() {
    const d = new Date();
    const pad = (x) => String(x).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
      d.getHours()
    )}:${pad(d.getMinutes())}`;
  }

  function getLang() {
    const stored = localStorage.getItem(STORAGE_LANG_KEY);
    if (stored === "ar" || stored === "en") return stored;
    return "en";
  }

  function setLang(lang) {
    localStorage.setItem(STORAGE_LANG_KEY, lang);
  }

  function ui(lang) {
    return TRANSLATIONS[lang] || TRANSLATIONS.en;
  }

  function translateUrlMessage(messageKey, lang) {
    if (lang === "ar") return URL_MESSAGES_AR[messageKey] || messageKey;
    return messageKey;
  }

  function stripUrlPunctuation(value) {
    let v = String(value || "").trim();
    v = v.replace(/^[<([{\"']+/, "");
    v = v.replace(/[)\]}>.,;:!?\"']+$/, "");
    return v.trim();
  }

  function looksLikeSingleUrl(input) {
    const value = stripUrlPunctuation(input);
    if (!value) return false;
    if (/\s/.test(value)) return false;
    if (value.includes("@")) return false;
    const re = /^(?:https?:\/\/|www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{2,5})?(?:\/[^\s]*)?$/i;
    return re.test(value);
  }

  function extractUrls(text) {
    const input = String(text || "");
    if (!input) return [];

    const matches = [];
    const spans = [];

    const httpRe = /https?:\/\/[^\s<>"]+/gi;
    const wwwRe = /\bwww\.[^\s<>"]+/gi;
    const bareRe = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{2,5})?(?:\/[^\s<>"]*)?\b/gi;

    const addMatch = (start, raw, end) => {
      const candidate = stripUrlPunctuation(raw);
      if (!candidate) return;
      if (/^mailto:/i.test(candidate)) return;
      matches.push([start, candidate]);
      if (typeof end === "number") spans.push([start, end]);
    };

    let m;
    while ((m = httpRe.exec(input)) !== null) addMatch(m.index, m[0], m.index + m[0].length);
    while ((m = wwwRe.exec(input)) !== null) addMatch(m.index, m[0], m.index + m[0].length);

    while ((m = bareRe.exec(input)) !== null) {
      const start = m.index;
      const end = m.index + m[0].length;
      if (start > 0 && input[start - 1] === "@") continue;
      let inside = false;
      for (let i = 0; i < spans.length; i++) {
        if (spans[i][0] <= start && start < spans[i][1]) {
          inside = true;
          break;
        }
      }
      if (inside) continue;
      addMatch(start, m[0], end);
    }

    matches.sort((a, b) => a[0] - b[0]);
    const urls = [];
    const seen = new Set();
    for (let i = 0; i < matches.length; i++) {
      const candidate = matches[i][1];
      const lower = candidate.toLowerCase();
      if (seen.has(lower)) continue;
      seen.add(lower);
      urls.push(candidate);
      if (urls.length >= MAX_URLS) break;
    }
    return urls;
  }

  function checkUrl(rawUrl) {
    let url = String(rawUrl || "").trim();
    if (!/^https?:\/\//i.test(url)) url = "http://" + url;

    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return { safe: false, messageKey: "Invalid URL format" };
    }

    const domain = (parsed.hostname || "").toLowerCase();
    if (!domain) return { safe: false, messageKey: "Invalid URL format" };

    for (let i = 0; i < SUSPICIOUS_WORDS.length; i++) {
      if (domain.includes(SUSPICIOUS_WORDS[i])) {
        return { safe: false, messageKey: "Suspicious keyword found in domain" };
      }
    }

    if ((domain.match(/\./g) || []).length > 3) {
      return { safe: false, messageKey: "Too many subdomains" };
    }

    return { safe: true, messageKey: "URL looks safe" };
  }

  function makeTokenRegex() {
    // Prefer Unicode-aware tokenization similar to Python's (?u)\\b\\w\\w+\\b
    try {
      // eslint-disable-next-line no-new
      return new RegExp("[\\p{L}\\p{N}_]{2,}", "gu");
    } catch {
      return /\b\w\w+\b/g;
    }
  }

  const TOKEN_RE = makeTokenRegex();

  function tokenize(text, lowercase) {
    let s = String(text || "");
    if (lowercase) s = s.toLowerCase();
    const tokens = [];
    let m;
    TOKEN_RE.lastIndex = 0;
    while ((m = TOKEN_RE.exec(s)) !== null) tokens.push(m[0]);
    return tokens;
  }

  function buildVector(text) {
    const vec = MODEL.vectorizer;
    const terms = vec.terms;
    const idf = vec.idf;
    const n = terms.length;

    const termToIndex = new Map();
    for (let i = 0; i < n; i++) termToIndex.set(terms[i], i);

    const counts = new Array(n).fill(0);
    const tokens = tokenize(text, !!vec.lowercase);
    for (let i = 0; i < tokens.length; i++) {
      const idx = termToIndex.get(tokens[i]);
      if (idx === undefined) continue;
      counts[idx] += 1;
    }

    const tfidf = new Array(n).fill(0);
    for (let i = 0; i < n; i++) {
      if (counts[i] === 0) continue;
      tfidf[i] = counts[i] * idf[i];
    }

    if (vec.norm === "l2") {
      let sumSq = 0;
      for (let i = 0; i < n; i++) sumSq += tfidf[i] * tfidf[i];
      const norm = Math.sqrt(sumSq);
      if (norm > 0) {
        for (let i = 0; i < n; i++) tfidf[i] = tfidf[i] / norm;
      }
    }

    return tfidf;
  }

  function sigmoid(x) {
    // Stable-ish sigmoid for our tiny models.
    if (x >= 0) {
      const z = Math.exp(-x);
      return 1 / (1 + z);
    }
    const z = Math.exp(x);
    return z / (1 + z);
  }

  function analyzeText(text, lang) {
    const x = buildVector(text);
    const coef = MODEL.model.coef;
    const intercept = MODEL.model.intercept;

    let score = intercept;
    for (let i = 0; i < x.length; i++) score += coef[i] * x[i];

    const probaUnsafe = sigmoid(score);
    const probaSafe = 1 - probaUnsafe;
    // Match scikit-learn LogisticRegression: class 1 only when decision_function > 0.
    const isUnsafe = score > 0;
    const resultClass = isUnsafe ? "unsafe" : "safe";
    const confidence = round2(Math.max(probaUnsafe, probaSafe) * 100);

    const strings = ui(lang);
    return {
      result_class: resultClass,
      label: strings[resultClass],
      confidence,
      icon: isUnsafe ? "⚠️" : "✅",
      message: isUnsafe ? strings.ml_unsafe_msg : strings.ml_safe_msg
    };
  }

  function summaryMessage(lang, textResultClass, urlsTotal, urlsUnsafe) {
    const strings = ui(lang);
    const textPart =
      textResultClass === "safe" || textResultClass === "unsafe"
        ? `${strings.text}: ${strings[textResultClass]}`
        : "";

    let urlsPart = strings.urls_none;
    if (urlsTotal) {
      if (lang === "ar") urlsPart = `${strings.urls}: ${urlsTotal} (${strings.unsafe}: ${urlsUnsafe})`;
      else urlsPart = `${strings.urls}: ${urlsTotal} checked (${urlsUnsafe} unsafe)`;
    }

    if (textPart) return `${textPart} • ${urlsPart}`;
    return urlsPart;
  }

  function analyzeInput(raw, lang) {
    const input = String(raw || "").slice(0, MAX_ANALYSIS_CHARS).trim();
    const urls = extractUrls(input);
    const isUrlOnly = looksLikeSingleUrl(input) && !/\s/.test(input);
    const strings = ui(lang);

    if (isUrlOnly) {
      const candidate = stripUrlPunctuation(input);
      const { safe, messageKey } = checkUrl(candidate);
      const resultClass = safe ? "safe" : "unsafe";
      const confidence = safe ? 90 : 85;
      const message = translateUrlMessage(messageKey, lang);

      return {
        kind: "url",
        input,
        result_class: resultClass,
        icon: safe ? "✅" : "⚠️",
        label: strings[resultClass],
        confidence,
        message,
        text_details: null,
        url_details: [
          {
            url: candidate,
            result_class: resultClass,
            icon: safe ? "✅" : "⚠️",
            label: strings[resultClass],
            confidence,
            message
          }
        ]
      };
    }

    const textDetails = analyzeText(input, lang);
    const urlDetails = [];
    let urlsUnsafe = 0;
    for (let i = 0; i < urls.length; i++) {
      const candidate = urls[i];
      const { safe, messageKey } = checkUrl(candidate);
      const resultClass = safe ? "safe" : "unsafe";
      if (!safe) urlsUnsafe += 1;

      urlDetails.push({
        url: candidate,
        result_class: resultClass,
        icon: safe ? "✅" : "⚠️",
        label: strings[resultClass],
        confidence: safe ? 90 : 85,
        message: translateUrlMessage(messageKey, lang)
      });
    }

    const urlsTotal = urlDetails.length;
    const overallUnsafe = textDetails.result_class === "unsafe" || urlsUnsafe > 0;
    const overallClass = overallUnsafe ? "unsafe" : "safe";

    // Overall confidence: mimic the server logic (worst-case if unsafe, best-case if safe).
    let overallConfidence = null;
    const candidates = [];
    if (overallClass === "unsafe") {
      if (textDetails.result_class === "unsafe") candidates.push(textDetails.confidence);
      for (let i = 0; i < urlDetails.length; i++) {
        if (urlDetails[i].result_class === "unsafe") candidates.push(urlDetails[i].confidence);
      }
      overallConfidence = candidates.length ? round2(Math.max(...candidates)) : null;
    } else {
      if (textDetails.result_class === "safe") candidates.push(textDetails.confidence);
      for (let i = 0; i < urlDetails.length; i++) {
        if (urlDetails[i].result_class === "safe") candidates.push(urlDetails[i].confidence);
      }
      overallConfidence = candidates.length ? round2(Math.min(...candidates)) : null;
    }

    const message =
      urlsTotal > 0
        ? summaryMessage(lang, textDetails.result_class, urlsTotal, urlsUnsafe)
        : textDetails.message;

    const kind = input.includes("\n") || urlsTotal > 0 ? "email" : "text";

    return {
      kind,
      input,
      result_class: overallClass,
      icon: overallClass === "unsafe" ? "⚠️" : "✅",
      label: strings[overallClass],
      confidence: overallConfidence,
      message,
      text_details: textDetails,
      url_details: urlDetails
    };
  }

  function loadHistory() {
    try {
      const raw = localStorage.getItem(STORAGE_HISTORY_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  function saveHistory(items) {
    try {
      localStorage.setItem(STORAGE_HISTORY_KEY, JSON.stringify(items.slice(-MAX_HISTORY)));
    } catch {
      // ignore quota errors
    }
  }

  function addToHistory(entry) {
    const items = loadHistory();
    items.push(entry);
    saveHistory(items);
  }

  function clearHistory() {
    localStorage.removeItem(STORAGE_HISTORY_KEY);
  }

  function el(id) {
    return document.getElementById(id);
  }

  function setText(id, value) {
    const node = el(id);
    if (node) node.textContent = value;
  }

  function setHidden(id, hidden) {
    const node = el(id);
    if (node) node.hidden = !!hidden;
  }

  function renderStrings(lang) {
    const strings = ui(lang);
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    document.title = strings.title;

    setText("brandName", strings.brand);
    setText("brandTag", strings.tagline);
    setText("heroTitle", strings.hero_title);
    setText("heroText", strings.hero_text);
    setText("badge1", strings.badge_1);
    setText("badge2", strings.badge_2);
    setText("badge3", strings.badge_3);
    setText("exampleLabel", strings.example_label + ":");
    setText("exampleText", strings.example_text);
    setText("feature1Title", strings.feature_1_title);
    setText("feature1Text", strings.feature_1_text);
    setText("feature2Title", strings.feature_2_title);
    setText("feature2Text", strings.feature_2_text);
    setText("feature3Title", strings.feature_3_title);
    setText("feature3Text", strings.feature_3_text);
    setText("scanTitle", strings.scan_title);
    setText("scanSubtitle", strings.scan_subtitle);
    setText("checkBtn", strings.check);
    setText("privacyNote", strings.privacy_note);
    setText("confidenceLabel", strings.confidence);
    setText("textAnalysisTitle", strings.text_analysis_title);
    setText("urlChecksTitle", strings.url_checks_title);
    setText("historyTitle", strings.history_title);
    setText("historyNote", strings.history_note);
    setText("historyEmpty", strings.history_empty);
    setText("clearHistoryBtn", strings.clear_history);
    setText("toggleLang", strings.toggle);
    setText("footerText", strings.footer);

    const input = el("inputText");
    if (input) input.placeholder = strings.placeholder;

    const installBtn = el("installApp");
    if (installBtn) installBtn.textContent = strings.install;
  }

  function renderHistory(lang) {
    const strings = ui(lang);
    const container = el("historyChat");
    if (!container) return;

    const items = loadHistory();
    container.innerHTML = "";

    setHidden("historyEmpty", items.length !== 0);

    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const kindLabel =
        it.kind === "url" ? strings.url : it.kind === "email" ? strings.email : strings.text;

      const user = document.createElement("div");
      user.className = "chat-block user";
      user.innerHTML = `
        <div class="chat-meta">
          <span class="chat-who">${strings.you}</span>
          <span class="chat-kind">${kindLabel}</span>
          <span class="chat-when">${it.at || ""}</span>
        </div>
        <div class="bubble bubble-user"></div>
      `;
      user.querySelector(".bubble").textContent = it.input || "";
      container.appendChild(user);

      const bot = document.createElement("div");
      bot.className = "chat-block bot";
      const confText = it.confidence === null || it.confidence === undefined ? "" : `${it.confidence}%`;
      bot.innerHTML = `
        <div class="bubble bubble-bot ${it.result_class}">
          <div class="bubble-title">
            <span class="bubble-icon" aria-hidden="true">${it.result_class === "safe" ? "✅" : "⚠️"}</span>
            <span class="bubble-label">${it.result_class === "safe" ? strings.safe : strings.unsafe}</span>
            <span class="bubble-conf">${confText}</span>
          </div>
          <div class="bubble-text"></div>
        </div>
      `;
      bot.querySelector(".bubble-text").textContent = it.message || "";
      container.appendChild(bot);
    }

    container.scrollTop = container.scrollHeight;
  }

  function renderUrls(lang, urlDetails) {
    const strings = ui(lang);
    const urlList = el("urlList");
    const urlCount = el("urlCount");
    const urlsNone = el("urlsNone");

    if (!urlList || !urlCount || !urlsNone) return;
    urlList.innerHTML = "";

    if (!urlDetails || urlDetails.length === 0) {
      urlCount.hidden = true;
      urlsNone.hidden = false;
      urlsNone.textContent = strings.urls_none;
      return;
    }

    urlCount.hidden = false;
    urlCount.textContent = String(urlDetails.length);
    urlsNone.hidden = true;

    for (let i = 0; i < urlDetails.length; i++) {
      const u = urlDetails[i];
      const item = document.createElement("div");
      item.className = `url-item ${u.result_class}`;
      item.innerHTML = `
        <div class="url-item-top">
          <span class="url-item-icon" aria-hidden="true">${u.icon}</span>
          <span class="url-item-label">${u.label}</span>
          <span class="url-item-conf">${u.confidence}%</span>
        </div>
        <div class="url-item-value"></div>
        <div class="url-item-msg"></div>
      `;
      item.querySelector(".url-item-value").textContent = u.url;
      item.querySelector(".url-item-msg").textContent = u.message;
      urlList.appendChild(item);
    }
  }

  function renderResult(lang, analysis) {
    const strings = ui(lang);

    setHidden("resultWrap", !analysis);
    if (!analysis) return;

    const resultBox = el("resultBox");
    if (!resultBox) return;

    resultBox.classList.remove("safe", "unsafe");
    resultBox.classList.add(analysis.result_class);

    setText("resultIcon", analysis.icon);
    setText("resultLabel", analysis.label);
    setText("resultMessage", analysis.message || "");

    const conf = analysis.confidence;
    const meter = el("overallMeter");
    const confValue = el("confidenceValue");
    const fill = el("overallFill");

    if (conf === null || conf === undefined) {
      if (meter) meter.hidden = true;
    } else {
      if (meter) meter.hidden = false;
      if (confValue) confValue.textContent = `${conf}%`;
      if (fill) fill.style.width = `${Math.max(0, Math.min(100, conf))}%`;
    }

    const textCard = el("textCard");
    const textMiniMeter = el("textMiniMeter");
    const textPill = el("textPill");

    if (analysis.text_details) {
      if (textCard) textCard.hidden = false;
      setText("textPillIcon", analysis.text_details.icon);
      setText("textPillLabel", analysis.text_details.label);
      setText("textDetailMessage", analysis.text_details.message);

      if (textPill) {
        textPill.classList.remove("safe", "unsafe");
        textPill.classList.add(analysis.text_details.result_class);
      }

      if (textMiniMeter) {
        textMiniMeter.classList.remove("safe", "unsafe");
        textMiniMeter.classList.add(analysis.text_details.result_class);
      }

      const tconf = analysis.text_details.confidence;
      setText("textMiniLabel", strings.confidence);
      setText("textMiniValue", `${tconf}%`);
      const tfill = el("textMiniFill");
      if (tfill) tfill.style.width = `${Math.max(0, Math.min(100, tconf))}%`;
    } else {
      if (textCard) textCard.hidden = true;
    }

    renderUrls(lang, analysis.url_details || []);
  }

  function initServiceWorker() {
    if (!("serviceWorker" in navigator)) return;
    // Service workers only work on HTTPS (or localhost). Android WebView file:// won't use it.
    if (location.protocol !== "https:" && location.hostname !== "localhost" && location.hostname !== "127.0.0.1")
      return;

    // Avoid reloading on first install; reload only when an update takes over.
    let hadController = !!navigator.serviceWorker.controller;
    window.addEventListener("load", () => {
      navigator.serviceWorker
        .register("./sw.js")
        .then((reg) => {
          try {
            reg.update();
          } catch (e) {}
        })
        .catch(() => {});
    });

    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (!hadController) {
        hadController = true;
        return;
      }
      if (window.__swReloading) return;
      window.__swReloading = true;
      window.location.reload();
    });
  }

  function initInstallButton(lang) {
    const installBtn = el("installApp");
    if (!installBtn) return;

    let deferredPrompt = null;

    window.addEventListener("beforeinstallprompt", (e) => {
      e.preventDefault();
      deferredPrompt = e;
      installBtn.hidden = false;
    });

    window.addEventListener("appinstalled", () => {
      deferredPrompt = null;
      installBtn.hidden = true;
    });

    installBtn.addEventListener("click", () => {
      if (!deferredPrompt) return;
      installBtn.disabled = true;
      deferredPrompt.prompt();
      deferredPrompt.userChoice
        .then(() => {
          deferredPrompt = null;
          installBtn.hidden = true;
        })
        .catch(() => {
          deferredPrompt = null;
        })
        .then(() => {
          installBtn.disabled = false;
        });
    });

    installBtn.textContent = ui(lang).install;
  }

  function init() {
    let lang = getLang();
    renderStrings(lang);
    renderHistory(lang);
    initServiceWorker();
    initInstallButton(lang);

    const toggle = el("toggleLang");
    if (toggle) {
      toggle.addEventListener("click", (e) => {
        e.preventDefault();
        lang = lang === "ar" ? "en" : "ar";
        setLang(lang);
        renderStrings(lang);
        renderHistory(lang);
      });
    }

    const clearBtn = el("clearHistoryBtn");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        clearHistory();
        renderHistory(lang);
      });
    }

    const form = el("scanForm");
    const input = el("inputText");
    if (form && input) {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const raw = String(input.value || "").trim();
        if (!raw) return;

        const analysis = analyzeInput(raw, lang);
        renderResult(lang, analysis);

        const snippet = raw.slice(0, MAX_HISTORY_SNIPPET_CHARS);
        addToHistory({
          at: nowStamp(),
          kind: analysis.kind,
          input: snippet,
          result_class: analysis.result_class,
          confidence: analysis.confidence,
          message: analysis.message
        });
        renderHistory(lang);
      });
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
