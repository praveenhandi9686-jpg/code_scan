import os, re, time, html, json
from collections import defaultdict, deque
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, jsonify, request, session, render_template, Response
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, CodeReview, Finding
from analyzers import analyze_code, score, label, dedupe, ORDER, LANG_KEY
from services.ai_service import ai_review
load_dotenv()

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.getenv("SECRET_KEY", "dev-only-change-me"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///codescan.db"),
        MAX_CONTENT_LENGTH=512 * 1024, MAX_CODE_CHARS=int(os.getenv("MAX_CODE_CHARS", 200000)),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production")
    if test_config: app.config.update(test_config)
    CORS(app, origins=os.getenv("CORS_ORIGINS", "http://127.0.0.1:5000").split(","), supports_credentials=True)
    db.init_app(app)
    with app.app_context(): db.create_all()

    hits = defaultdict(deque)
    def limited(key, n, per=60):
        q, t = hits[key], time.time()
        while q and q[0] < t - per: q.popleft()
        q.append(t); return len(q) > n

    def err(msg, code): return jsonify(success=False, error=msg), code

    @app.before_request
    def csrf_and_limit():
        if request.path.startswith("/api/"):
            if request.method in ("POST", "PUT", "DELETE") and request.headers.get("X-Requested-With") != "fetch":
                return err("Missing CSRF header.", 403)
            if limited((request.remote_addr, request.path.split("/")[2]), 60): return err("Too many requests.", 429)

    @app.after_request
    def headers(r):
        r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'"})
        return r

    @app.errorhandler(413)
    def too_big(e): return err("Submission is too large.", 413)
    @app.errorhandler(500)
    def server_err(e): return err("Unable to process the request.", 500)

    def login_required(f):
        @wraps(f)
        def w(*a, **k):
            if not session.get("uid"): return err("Authentication required.", 401)
            return f(*a, **k)
        return w

    @app.get("/")
    def index(): return render_template("index.html")
    @app.get("/api/health")
    def health(): return jsonify(success=True, status="ok")

    # ---- auth
    @app.post("/api/auth/register")
    def register():
        d = request.get_json(silent=True) or {}
        u, e, p = (d.get("username") or "").strip(), (d.get("email") or "").strip().lower(), d.get("password") or ""
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", u): return err("Username must be 3-30 letters, digits or underscores.", 422)
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e): return err("Invalid email address.", 422)
        if len(p) < 8 or not re.search(r"[A-Za-z]", p) or not re.search(r"\d", p): return err("Password needs 8+ characters with letters and digits.", 422)
        if p != d.get("confirm_password"): return err("Passwords do not match.", 422)
        if User.query.filter((User.username == u) | (User.email == e)).first(): return err("Username or email already in use.", 400)
        user = User(username=u, email=e, password_hash=generate_password_hash(p))
        db.session.add(user); db.session.commit()
        return jsonify(success=True), 201

    @app.post("/api/auth/login")
    def login():
        d = request.get_json(silent=True) or {}
        if limited(("login", request.remote_addr), 10): return err("Too many login attempts.", 429)
        user = User.query.filter_by(email=(d.get("email") or "").strip().lower()).first()
        if not user or not check_password_hash(user.password_hash, d.get("password") or ""): return err("Invalid credentials.", 401)
        session.clear(); session["uid"] = user.id
        return jsonify(success=True, user={"username": user.username, "email": user.email})

    @app.post("/api/auth/logout")
    def logout(): session.clear(); return jsonify(success=True)

    @app.get("/api/auth/me")
    @login_required
    def me():
        u = db.session.get(User, session["uid"])
        return jsonify(success=True, user={"username": u.username, "email": u.email})

    # ---- analysis
    def run_analysis(d):
        lang, src = (d.get("language") or "").lower(), d.get("code")
        if not isinstance(src, str) or not src.strip(): raise ValueError("Please enter source code before starting the review.")
        if lang not in LANG_KEY: raise ValueError("Unsupported language.")
        if len(src) > app.config["MAX_CODE_CHARS"]: raise ValueError(f"Code exceeds the {app.config['MAX_CODE_CHARS']} character limit.")
        found = analyze_code(lang, src)
        summary, ai, status = ai_review(lang, src, [f["title"] for f in found])
        found = dedupe(found + ai)
        sc = score(found)
        if not summary: summary = f"{len(found)} issue(s) found. Rating: {label(sc['overall'])}." if found else "No issues detected by the enabled analyzers."
        return dict(language=lang, summary=summary, ai_status=status, scores=sc, rating=label(sc["overall"]), findings=found)

    @app.post("/api/analyze")
    @login_required
    def analyze():
        try: return jsonify(success=True, **run_analysis(request.get_json(silent=True) or {}))
        except ValueError as e: return err(str(e), 422)
        except Exception as e: app.logger.exception("analysis failed"); return err("Unable to analyze the submitted code.", 500)

    def review_dict(r, full=False):
        fs = r.findings
        top = max((f.severity for f in fs), key=ORDER.index, default="NONE")
        d = dict(id=r.id, language=r.language, overall_score=r.overall_score, security_score=r.security_score,
                 quality_score=r.quality_score, maintainability_score=r.maintainability_score, reliability_score=r.reliability_score,
                 issue_count=len(fs), highest_severity=top, summary=r.summary, ai_status=r.ai_status, created_at=r.created_at.isoformat())
        if full: d.update(source_code=r.source_code, findings=[f.to_dict() for f in sorted(fs, key=lambda f: (-ORDER.index(f.severity), f.line_number or 0))])
        return d

    def owned(rid):
        r = db.session.get(CodeReview, rid)
        return r if r and r.user_id == session["uid"] else None   # 404 for others' reviews: no existence leak

    @app.post("/api/reviews")
    @login_required
    def create_review():
        try: res = run_analysis(request.get_json(silent=True) or {})
        except ValueError as e: return err(str(e), 422)
        except Exception: app.logger.exception("analysis failed"); return err("Unable to analyze the submitted code.", 500)
        s = res["scores"]
        r = CodeReview(user_id=session["uid"], language=res["language"], source_code=request.get_json()["code"], overall_score=s["overall"],
            security_score=s["security"], quality_score=s["quality"], maintainability_score=s["maintainability"],
            reliability_score=s["reliability"], summary=res["summary"], ai_status=res["ai_status"])
        r.findings = [Finding(**{k: f[k] for k in Finding.FIELDS}) for f in res["findings"]]
        db.session.add(r); db.session.commit()
        return jsonify(success=True, review=review_dict(r, True), rating=res["rating"]), 201

    @app.get("/api/reviews")
    @login_required
    def list_reviews():
        rs = CodeReview.query.filter_by(user_id=session["uid"]).order_by(CodeReview.created_at.desc()).all()
        return jsonify(success=True, reviews=[review_dict(r) for r in rs])

    @app.get("/api/reviews/<int:rid>")
    @login_required
    def get_review(rid):
        r = owned(rid)
        return jsonify(success=True, review=review_dict(r, True)) if r else err("Review not found.", 404)

    @app.delete("/api/reviews/<int:rid>")
    @login_required
    def delete_review(rid):
        r = owned(rid)
        if not r: return err("Review not found.", 404)
        db.session.delete(r); db.session.commit(); return jsonify(success=True)

    @app.get("/api/reviews/<int:rid>/report")
    @login_required
    def report(rid):
        r = owned(rid)
        if not r: return err("Review not found.", 404)
        d = review_dict(r, True); d.pop("source_code")
        if request.args.get("format") == "json":
            return Response(json.dumps(d, indent=2), mimetype="application/json", headers={"Content-Disposition": f"attachment; filename=codescan-{rid}.json"})
        e = html.escape
        rows = "".join(f"<h3>[{e(f['severity'])}] {e(f['title'])} <small>({e(f['category'])}, line {f['line_number']}, {e(f['status'])})</small></h3><pre>{e(f['code'])}</pre><p><b>Why:</b> {e(f['explanation'])}<br><b>Impact:</b> {e(f['impact'])}<br><b>Recommendation:</b> {e(f['recommendation'])}</p>" + (f"<pre>{e(f['suggested_fix'])}</pre>" if f["suggested_fix"] else "") for f in d["findings"])
        page = f"<!doctype html><meta charset=utf-8><title>CodeScan report {rid}</title><body style='font-family:sans-serif;max-width:800px;margin:auto'><h1>CodeScan</h1><p>AI Code Reviewer &amp; Bug Detection System</p><p>Review #{rid} · {e(d['language'])} · {e(d['created_at'])}</p><h2>Overall {d['overall_score']}/100</h2><p>Security {d['security_score']} · Quality {d['quality_score']} · Maintainability {d['maintainability_score']} · Reliability {d['reliability_score']}</p><h2>Detected issues ({d['issue_count']})</h2>{rows or '<p>None.</p>'}"
        return Response(page, mimetype="text/html", headers={"Content-Disposition": f"attachment; filename=codescan-{rid}.html"})
    return app

if __name__ == "__main__":
    create_app().run(debug=os.getenv("FLASK_ENV") == "development")
