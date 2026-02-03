from flask import Flask, render_template, request
from flask import make_response
import joblib
from url_checker import check_url
from flask import redirect, session, url_for
from flask import send_from_directory
from datetime import datetime
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")

# Load ML model correctly (joblib, NOT pickle)
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

MAX_HISTORY = 12
MAX_ANALYSIS_CHARS = 8000
MAX_HISTORY_SNIPPET_CHARS = 180
MAX_URLS = 10
APK_FILENAME = "SafeScan.apk"
DOWNLOADS_DIR = os.path.join(app.root_path, "static", "downloads")

TRANSLATIONS = {
    "en": {
        "title": "SafeScan • Message & URL Safety Checker",
        "brand": "SafeScan",
        "tagline": "Phishing & scam detection",
        "hero_title": "Detect suspicious links and messages in seconds.",
        "hero_text": "Paste a URL or text. We combine URL heuristics with an ML classifier to flag risky content and show a confidence score.",
        "badge_1": "URL heuristics",
        "badge_2": "ML classifier",
        "badge_3": "Confidence meter",
        "example_label": "Example",
        "example_text": "secure-login-paypal.com",
        "feature_1_title": "URL checks",
        "feature_1_text": "Flags suspicious domains, subdomains, and phishing patterns.",
        "feature_2_title": "Text scanning",
        "feature_2_text": "Classifies messages as safe or unsafe using your trained model.",
        "feature_3_title": "Clear results",
        "feature_3_text": "Readable explanations and a simple risk signal.",
        "scan_title": "Scan now",
        "scan_subtitle": "Paste a URL or message to analyse.",
        "placeholder": "Enter text or URL...",
        "check": "Check",
        "confidence": "Confidence",
        "safe": "Safe",
        "unsafe": "Unsafe",
        "ml_safe_msg": "No obvious red flags were detected in the text.",
        "ml_unsafe_msg": "This text looks suspicious and may be phishing or a scam.",
        "privacy_note": "Input is only used to generate this result.",
        "history_title": "History",
        "history_empty": "No scans yet. Your previous checks will appear here.",
        "history_note": "History is stored for this browser session.",
        "clear_history": "Clear",
        "you": "You",
        "url": "URL",
        "urls": "URLs",
        "text": "Text",
        "email": "Email",
        "text_analysis_title": "Text analysis",
        "url_checks_title": "URL checks",
        "urls_none": "No URLs detected in this input.",
        "install": "Install",
        "download_app": "Download",
        "download_title": "Download SafeScan",
        "download_text": "Install SafeScan on your phone (recommended) or download the Android APK.",
        "download_install_hint": "If you see the Install button in the header, tap it to add SafeScan to your home screen.",
        "download_apk": "Download Android APK",
        "apk_note": "If Android blocks the install, enable \"Install unknown apps\" for your browser, then try again.",
        "apk_missing": "APK is not uploaded yet.",
        "back_to_scan": "Back to scanner",
        "footer": "Educational project • Always verify before you click.",
        "toggle": "العربية",
    },
    "ar": {
        "title": "SafeScan • فاحص أمان الرسائل والروابط",
        "brand": "SafeScan",
        "tagline": "كشف التصيّد والاحتيال",
        "hero_title": "اكشف الروابط والرسائل المشبوهة خلال ثوانٍ.",
        "hero_text": "الصق رابطًا أو نصًا. نجمع بين فحص الروابط ونموذج تعلم آلي لاكتشاف المحتوى الخطِر وعرض مستوى الثقة.",
        "badge_1": "فحص الروابط",
        "badge_2": "نموذج تعلم آلي",
        "badge_3": "مؤشر الثقة",
        "example_label": "مثال",
        "example_text": "secure-login-paypal.com",
        "feature_1_title": "فحص الروابط",
        "feature_1_text": "يرصد النطاقات والكلمات والأنماط الشائعة في التصيّد.",
        "feature_2_title": "تحليل الرسائل",
        "feature_2_text": "يصنّف الرسائل إلى آمنة أو غير آمنة باستخدام النموذج المدرَّب.",
        "feature_3_title": "نتيجة واضحة",
        "feature_3_text": "شرح مبسّط مع إشارة واضحة للمخاطر.",
        "scan_title": "تحقق الآن",
        "scan_subtitle": "الصق رابطًا أو رسالة للتحليل.",
        "placeholder": "اكتب رسالة أو رابط...",
        "check": "تحقق",
        "confidence": "مستوى الثقة",
        "safe": "آمن",
        "unsafe": "غير آمن",
        "ml_safe_msg": "لم يتم رصد مؤشرات واضحة على الخطر في النص.",
        "ml_unsafe_msg": "يبدو هذا النص مشبوهًا وقد يكون تصيّدًا أو احتيالًا.",
        "privacy_note": "يُستخدم الإدخال فقط لإظهار النتيجة.",
        "history_title": "السجل",
        "history_empty": "لا يوجد سجل بعد. ستظهر نتائج التحقق السابقة هنا.",
        "history_note": "يتم حفظ السجل في جلسة المتصفح الحالية.",
        "clear_history": "مسح",
        "you": "أنت",
        "url": "رابط",
        "urls": "الروابط",
        "text": "نص",
        "email": "بريد",
        "text_analysis_title": "تحليل النص",
        "url_checks_title": "فحص الروابط",
        "urls_none": "لم يتم العثور على روابط في هذا النص.",
        "install": "تثبيت",
        "download_app": "تحميل",
        "download_title": "تحميل SafeScan",
        "download_text": "ثبّت التطبيق على هاتفك (مستحسن) أو حمّل ملف APK للأندرويد.",
        "download_install_hint": "إذا ظهر زر التثبيت في الأعلى، اضغط عليه لإضافة SafeScan إلى الشاشة الرئيسية.",
        "download_apk": "تحميل APK للأندرويد",
        "apk_note": "إذا منع الأندرويد التثبيت، فعّل خيار \"تثبيت التطبيقات غير المعروفة\" للمتصفح ثم حاول مرة أخرى.",
        "apk_missing": "لم يتم رفع ملف APK بعد.",
        "back_to_scan": "العودة للفحص",
        "footer": "مشروع تعليمي • تحقّق دائمًا قبل الضغط على أي رابط.",
        "toggle": "English",
    },
}

ARABIC_URL_MESSAGES = {
    "Invalid URL format": "صيغة الرابط غير صحيحة",
    "Suspicious keyword found in domain": "تم العثور على كلمة مشبوهة في النطاق",
    "Too many subdomains": "يوجد عدد كبير من النطاقات الفرعية",
    "URL looks safe": "يبدو الرابط آمنًا",
}


def _translate_url_message(message_key: str, lang: str) -> str:
    if lang == "ar":
        return ARABIC_URL_MESSAGES.get(message_key, message_key)
    return message_key


_HTTP_URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
_WWW_URL_RE = re.compile(r"\bwww\.[^\s<>\"]+", re.IGNORECASE)
_BARE_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{2,5})?(?:/[^\s<>\"]*)?\b",
    re.IGNORECASE,
)
_SINGLE_URL_RE = re.compile(
    r"^(?:https?://|www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{2,5})?(?:/[^\s]*)?$",
    re.IGNORECASE,
)


def _strip_url_punctuation(value: str) -> str:
    value = (value or "").strip()
    value = value.lstrip("<([{\"'")
    value = value.rstrip(")]}>.,;:!?\"'")
    return value.strip()


def _looks_like_single_url(value: str) -> bool:
    value = _strip_url_punctuation(value)
    if not value or re.search(r"\s", value):
        return False
    if "@" in value:
        return False
    return bool(_SINGLE_URL_RE.fullmatch(value))


def _extract_urls(text: str):
    if not text:
        return []

    matches = []
    spans = []

    for regex in (_HTTP_URL_RE, _WWW_URL_RE):
        for m in regex.finditer(text):
            candidate = _strip_url_punctuation(m.group(0))
            if not candidate:
                continue
            lower = candidate.lower()
            if lower.startswith("mailto:"):
                continue

            matches.append((m.start(), candidate))
            spans.append((m.start(), m.end()))

    for m in _BARE_DOMAIN_RE.finditer(text):
        if m.start() > 0 and text[m.start() - 1] == "@":
            continue
        if any(start <= m.start() < end for start, end in spans):
            continue

        candidate = _strip_url_punctuation(m.group(0))
        if not candidate:
            continue

        matches.append((m.start(), candidate))

    matches.sort(key=lambda x: x[0])

    urls = []
    seen = set()
    for _, candidate in matches:
        lower = candidate.lower()
        if lower in seen:
            continue
        seen.add(lower)
        urls.append(candidate)
        if len(urls) >= MAX_URLS:
            break

    return urls


def _analyze_text(text: str, ui: dict):
    X = vectorizer.transform([text])
    proba = model.predict_proba(X)[0]
    confidence = round(float(max(proba)) * 100, 2)

    is_unsafe = int(model.predict(X)[0]) == 1
    result_class = "unsafe" if is_unsafe else "safe"

    return {
        "result_class": result_class,
        "label": ui[result_class],
        "confidence": confidence,
        "icon": "⚠️" if is_unsafe else "✅",
        "message": ui["ml_unsafe_msg"] if is_unsafe else ui["ml_safe_msg"],
    }


def _history_summary_message(lang: str, ui: dict, text_result_class: str, urls_total: int, urls_unsafe: int):
    text_part = ""
    if text_result_class in ("safe", "unsafe"):
        text_part = f"{ui['text']}: {ui[text_result_class]}"

    if urls_total:
        if lang == "ar":
            urls_part = f"{ui['urls']}: {urls_total} ({ui['unsafe']}: {urls_unsafe})"
        else:
            urls_part = f"{ui['urls']}: {urls_total} checked ({urls_unsafe} unsafe)"
    else:
        urls_part = ui["urls_none"]

    if text_part:
        return f"{text_part} • {urls_part}"
    return urls_part


def _build_history_view(history_items, lang: str, ui: dict):
    view = []
    for item in history_items or []:
        result_class = item.get("result_class")
        if result_class not in ("safe", "unsafe"):
            continue

        kind = item.get("kind", "text")
        message_type = item.get("message_type", "ml")
        message_key = item.get("message_key", "")

        if message_type == "url":
            msg = _translate_url_message(message_key, lang)
        elif message_type == "summary":
            msg = _history_summary_message(
                lang,
                ui,
                item.get("text_result_class", ""),
                int(item.get("urls_total", 0) or 0),
                int(item.get("urls_unsafe", 0) or 0),
            )
        else:
            msg = ui["ml_safe_msg"] if result_class == "safe" else ui["ml_unsafe_msg"]

        view.append(
            {
                "at": item.get("at", ""),
                "kind": kind if kind in ("url", "text", "email") else "text",
                "input": item.get("input", ""),
                "result_class": result_class,
                "confidence": item.get("confidence"),
                "icon": "✅" if result_class == "safe" else "⚠️",
                "message": msg,
            }
        )
    return view


@app.route("/sw.js", methods=["GET"])
def service_worker():
    """Serve the service worker from the site root so it can control '/' (PWA install criteria)."""
    resp = make_response(
        send_from_directory(app.static_folder, "sw.js", mimetype="application/javascript")
    )
    # Ensure the browser checks for updated SW on each visit/deploy.
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    # Allow root scope even if a host rewrites SW URLs.
    resp.headers["Service-Worker-Allowed"] = "/"
    return resp


@app.route("/download", methods=["GET"])
def download_page():
    lang = (request.args.get("lang") or "en").lower()
    if lang not in TRANSLATIONS:
        lang = "en"
    ui = TRANSLATIONS[lang]

    apk_path = os.path.join(DOWNLOADS_DIR, APK_FILENAME)
    apk_available = os.path.isfile(apk_path)

    return render_template(
        "download.html",
        ui=ui,
        lang=lang,
        direction="rtl" if lang == "ar" else "ltr",
        toggle_lang="en" if lang == "ar" else "ar",
        apk_available=apk_available,
    )


@app.route("/download/android", methods=["GET"])
def download_android():
    lang = (request.args.get("lang") or "en").lower()
    if lang not in TRANSLATIONS:
        lang = "en"

    apk_path = os.path.join(DOWNLOADS_DIR, APK_FILENAME)
    if not os.path.isfile(apk_path):
        return redirect(url_for("download_page", lang=lang))

    return send_from_directory(
        DOWNLOADS_DIR,
        APK_FILENAME,
        as_attachment=True,
        mimetype="application/vnd.android.package-archive",
    )


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    result_class = None
    confidence = None
    icon = None
    message = ""
    user_input = ""
    text_details = None
    url_details = []

    lang = (request.values.get("lang") or "en").lower()
    if lang not in TRANSLATIONS:
        lang = "en"
    ui = TRANSLATIONS[lang]

    if request.method == "POST" and request.form.get("action") == "clear_history":
        session.pop("history", None)
        return redirect(url_for("home", lang=lang))

    history = session.get("history", [])
    if not isinstance(history, list):
        history = []

    if request.method == "POST" and request.form.get("action") == "scan":
        raw_input = request.form.get("text", "").strip()
        analysis_input = raw_input[:MAX_ANALYSIS_CHARS]
        user_input = analysis_input

        history_input = analysis_input[:MAX_HISTORY_SNIPPET_CHARS]
        urls = _extract_urls(analysis_input)
        is_url_only = _looks_like_single_url(analysis_input) and not re.search(r"\s", analysis_input)

        if is_url_only:
            candidate = _strip_url_punctuation(analysis_input)
            safe, msg_key = check_url(candidate)
            url_conf = 90 if safe else 85

            result_class = "safe" if safe else "unsafe"
            result = ui[result_class]
            icon = "✅" if safe else "⚠️"
            confidence = url_conf
            message = _translate_url_message(msg_key, lang)

            url_details = [
                {
                    "url": candidate,
                    "result_class": result_class,
                    "label": ui[result_class],
                    "icon": icon,
                    "confidence": url_conf,
                    "message": message,
                }
            ]

            if history_input and result_class:
                history.append(
                    {
                        "at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                        "kind": "url",
                        "input": history_input,
                        "result_class": result_class,
                        "confidence": confidence,
                        "message_type": "url",
                        "message_key": msg_key,
                    }
                )

        else:
            text_details = _analyze_text(analysis_input, ui)

            urls_unsafe = 0
            url_details = []
            for candidate in urls:
                safe, msg_key = check_url(candidate)
                url_conf = 90 if safe else 85
                url_result_class = "safe" if safe else "unsafe"
                if not safe:
                    urls_unsafe += 1

                url_details.append(
                    {
                        "url": candidate,
                        "result_class": url_result_class,
                        "label": ui[url_result_class],
                        "icon": "✅" if safe else "⚠️",
                        "confidence": url_conf,
                        "message": _translate_url_message(msg_key, lang),
                    }
                )

            urls_total = len(url_details)
            overall_unsafe = (text_details["result_class"] == "unsafe") or (urls_unsafe > 0)

            result_class = "unsafe" if overall_unsafe else "safe"
            result = ui[result_class]
            icon = "⚠️" if overall_unsafe else "✅"

            if result_class == "unsafe":
                candidates = []
                if text_details["result_class"] == "unsafe":
                    candidates.append(text_details["confidence"])
                candidates.extend([d["confidence"] for d in url_details if d["result_class"] == "unsafe"])
                confidence = round(max(candidates), 2) if candidates else None
            else:
                candidates = []
                if text_details["result_class"] == "safe":
                    candidates.append(text_details["confidence"])
                candidates.extend([d["confidence"] for d in url_details if d["result_class"] == "safe"])
                confidence = round(min(candidates), 2) if candidates else None

            if urls_total > 0:
                message = _history_summary_message(lang, ui, text_details["result_class"], urls_total, urls_unsafe)
            else:
                message = text_details["message"]

            kind = "email" if ("\n" in analysis_input or urls_total > 0) else "text"
            message_type = "summary" if urls_total > 0 else "ml"

            if history_input and result_class:
                item = {
                    "at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "kind": kind,
                    "input": history_input,
                    "result_class": result_class,
                    "confidence": confidence,
                    "message_type": message_type,
                    "message_key": "",
                }
                if message_type == "summary":
                    item["text_result_class"] = text_details["result_class"]
                    item["urls_total"] = urls_total
                    item["urls_unsafe"] = urls_unsafe

                history.append(item)

        if isinstance(history, list):
            session["history"] = history[-MAX_HISTORY:]
            session.modified = True

    return render_template(
        "index.html",
        ui=ui,
        result=result,
        result_class=result_class,
        confidence=confidence,
        icon=icon,
        message=message,
        user_input=user_input,
        text_details=text_details,
        url_details=url_details,
        history=_build_history_view(session.get("history", []), lang, ui),
        lang=lang,
        direction="rtl" if lang == "ar" else "ltr",
        toggle_lang="en" if lang == "ar" else "ar",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
