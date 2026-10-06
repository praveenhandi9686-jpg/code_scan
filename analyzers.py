"""Static analysis engine: per-language analyzers + scoring.
Scoring: each finding costs points = SEVERITY_WEIGHT * STATUS_FACTOR.
Overall = 100 - total cost (min 0). Sub-scores use only their categories."""
import ast, re
from html.parser import HTMLParser

SEV = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 0}
STATUS = {"Confirmed": 1.0, "Potential": 0.6, "Suggestion": 0.3}
ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def F(line, code, cat, sev, title, why, impact, rec, fix="", conf=0.8, status="Potential"):
    return dict(category=cat, severity=sev, title=title, line_number=line, code=(code or "").strip()[:300],
                explanation=why, impact=impact, recommendation=rec, suggested_fix=fix,
                confidence=conf, status=status, source="static")

SECRET = r"""(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*["'][^"']{4,}["']"""
SQLCAT = r"""(?i)(["'](select|insert|update|delete)\b[^"']*["']\s*\+|\bexecute\w*\(\s*f["'])"""
# (languages, regex, category, severity, title, why, impact, recommendation, fix, status)
RULES = [
 ("all", SECRET, "Security", "HIGH", "Hardcoded credential", "A secret appears to be embedded in source.", "Anyone with repo access can read it.", "Load secrets from environment variables.", "value = os.environ['SECRET_NAME']", "Potential"),
 ("all", SQLCAT, "Security", "HIGH", "Possible SQL injection", "SQL is built by string concatenation/formatting.", "Attackers may alter the query.", "Use parameterized queries.", "cursor.execute('SELECT * FROM users WHERE name = %s', (username,))", "Potential"),
 ("js", r"\beval\s*\(", "Security", "HIGH", "Use of eval()", "eval executes arbitrary strings as code.", "Code injection.", "Avoid eval; parse data with JSON.parse.", "", "Confirmed"),
 ("js", r"\.innerHTML\s*=|document\.write\s*\(", "Security", "MEDIUM", "Unsafe DOM write (XSS risk)", "Raw HTML is inserted into the DOM.", "XSS if the value is user-controlled.", "Use textContent or sanitize.", "el.textContent = value;", "Potential"),
 ("js", r"^\s*var\s+", "Quality", "LOW", "var used instead of let/const", "var is function-scoped and hoisted.", "Scope bugs.", "Use const or let.", "", "Suggestion"),
 ("js", r"[^=!]==[^=]", "Bug", "LOW", "Loose equality (==)", "== performs type coercion.", "Unexpected comparisons.", "Use ===.", "", "Suggestion"),
 ("js", r"catch\s*\([^)]*\)\s*\{\s*\}", "Bug", "MEDIUM", "Empty catch block", "Errors are silently swallowed.", "Failures go unnoticed.", "Handle or log the error.", "", "Confirmed"),
 ("js", r"setInterval\(\s*[\"']|setTimeout\(\s*[\"']", "Security", "MEDIUM", "String passed to timer", "Behaves like eval.", "Code injection.", "Pass a function.", "", "Confirmed"),
 ("py", r"\b(pickle|marshal)\.loads?\(|yaml\.load\((?!.*Loader)", "Security", "HIGH", "Unsafe deserialization", "Untrusted data can run code when deserialized.", "Remote code execution.", "Use json or yaml.safe_load.", "yaml.safe_load(data)", "Potential"),
 ("py", r"\b(md5|sha1)\b\s*\(|hashlib\.(md5|sha1)", "Security", "MEDIUM", "Weak hash algorithm", "MD5/SHA1 are broken for security use.", "Forgeable hashes.", "Use SHA-256+ or a password hasher.", "", "Potential"),
 ("py", r"requests\.\w+\([^)]*verify\s*=\s*False", "Security", "MEDIUM", "TLS verification disabled", "Certificates are not checked.", "Man-in-the-middle.", "Remove verify=False.", "", "Confirmed"),
 ("java", r"Runtime\.getRuntime\(\)\.exec|new ProcessBuilder", "Security", "HIGH", "OS command execution", "Process spawning with possibly tainted input.", "Command injection.", "Validate input / avoid shell.", "", "Potential"),
 ("java", r"\.printStackTrace\(\)", "Quality", "LOW", "printStackTrace used", "Stack traces go to stderr unlogged.", "Leaks details, poor observability.", "Use a logger.", "", "Suggestion"),
 ("java", r"catch\s*\([^)]*\)\s*\{\s*\}", "Bug", "MEDIUM", "Empty catch block", "Exception swallowed.", "Hidden failures.", "Handle or log.", "", "Confirmed"),
 ("java", r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", "Security", "MEDIUM", "Weak hash algorithm", "MD5/SHA1 are weak.", "Forgeable hashes.", "Use SHA-256+.", "", "Confirmed"),
 ("css", r"!important", "Quality", "LOW", "!important used", "Overrides cascade.", "Hard to maintain.", "Fix specificity instead.", "", "Suggestion"),
 ("css", r"\{\s*\}", "Quality", "LOW", "Empty rule", "Rule has no declarations.", "Dead code.", "Remove it.", "", "Confirmed"),
]
LANG_KEY = {"python": "py", "javascript": "js", "java": "java", "css": "css", "html": "html"}

def run_rules(lang, lines):
    k, out = LANG_KEY[lang], []
    for langs, rx, cat, sev, title, why, imp, rec, fix, status in RULES:
        if langs not in ("all", k): continue
        r = re.compile(rx)
        for i, ln in enumerate(lines, 1):
            if ln.strip().startswith(("#", "//")): continue
            if r.search(ln): out.append(F(i, ln, cat, sev, title, why, imp, rec, fix, 0.75, status))
    return out

class PythonAnalyzer:
    def analyze(self, src, lines):
        out = []
        try: tree = ast.parse(src)
        except SyntaxError as e:
            return [F(e.lineno or 1, lines[(e.lineno or 1) - 1] if lines else "", "Bug", "CRITICAL", "Syntax error",
                      str(e.msg), "Code will not run.", "Fix the syntax.", conf=1.0, status="Confirmed")]
        line = lambda n: lines[n - 1] if 0 < n <= len(lines) else ""
        for n in ast.walk(tree):
            ln = getattr(n, "lineno", 1)
            if isinstance(n, ast.Call):
                name = ast.unparse(n.func)
                if name in ("eval", "exec"):
                    out.append(F(ln, line(ln), "Security", "HIGH", f"Dangerous {name}()", f"{name} runs arbitrary code.", "Code injection.", "Use ast.literal_eval or explicit logic.", conf=0.95, status="Confirmed"))
                if name.startswith(("subprocess.", "os.system")) and (name == "os.system" or any(k.arg == "shell" and getattr(k.value, "value", None) is True for k in n.keywords)):
                    out.append(F(ln, line(ln), "Security", "HIGH", "Shell command execution", "Shell invocation may include user input.", "Command injection.", "Pass an argument list with shell=False.", "subprocess.run(['ls', path], check=True)", 0.8))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for d in n.args.defaults + [x for x in n.args.kw_defaults if x]:
                    if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                        out.append(F(d.lineno, line(d.lineno), "Bug", "MEDIUM", "Mutable default argument", "Default is shared across calls.", "State leaks between calls.", "Default to None and create inside.", "def f(x=None):\n    x = [] if x is None else x", 0.95, "Confirmed"))
                if len(n.body) == 1 and isinstance(n.body[0], ast.Pass):
                    out.append(F(ln, line(ln), "Quality", "LOW", "Empty function", f"{n.name} does nothing.", "Dead/unfinished code.", "Implement or remove.", conf=0.9, status="Confirmed"))
                if len(n.body) > 60: out.append(F(ln, line(ln), "Maintainability", "LOW", "Very long function", f"{n.name} has {len(n.body)} statements.", "Hard to test.", "Split into smaller functions.", conf=0.7, status="Suggestion"))
            if isinstance(n, ast.ExceptHandler):
                if n.type is None: out.append(F(ln, line(ln), "Bug", "MEDIUM", "Bare except", "Catches everything incl. KeyboardInterrupt.", "Hides bugs.", "Catch specific exceptions.", "except ValueError as e:", 0.95, "Confirmed"))
                elif len(n.body) == 1 and isinstance(n.body[0], ast.Pass): out.append(F(ln, line(ln), "Bug", "MEDIUM", "Exception silently ignored", "Handler does nothing.", "Failures unnoticed.", "Log or handle.", conf=0.9, status="Confirmed"))
            if isinstance(n, ast.While) and isinstance(n.test, ast.Constant) and n.test.value is True and not any(isinstance(x, (ast.Break, ast.Return)) for x in ast.walk(n)):
                out.append(F(ln, line(ln), "Bug", "MEDIUM", "Possible infinite loop", "while True with no break/return.", "Hang.", "Add exit condition.", conf=0.7))
        try:
            from pyflakes.checker import Checker
            for m in sorted(Checker(tree, "submitted").messages, key=lambda m: m.lineno):
                undefined = "undefined name" in m.message % m.message_args
                out.append(F(m.lineno, line(m.lineno), "Bug" if undefined else "Quality", "HIGH" if undefined else "LOW",
                             "Undefined name" if undefined else "Unused import/variable", m.message % m.message_args,
                             "NameError at runtime." if undefined else "Clutter.", "Define or remove it.", conf=0.9, status="Confirmed"))
        except ImportError: pass
        return out + run_rules("python", lines)

class HTMLAnalyzer(HTMLParser):
    VOID = {"meta","link","img","br","hr","input","area","base","col","embed","source","track","wbr","!doctype"}
    def analyze(self, src, lines):
        self.out, self.stack, self.src_lines = [], [], lines
        self.convert_charrefs = True; self.feed(src); self.close()
        for tag, ln in self.stack: self.out.append(F(ln, lines[ln-1], "Bug", "MEDIUM", f"Unclosed <{tag}>", "No closing tag found.", "Broken layout.", "Close the tag.", conf=0.7))
        if "<html" in src.lower() and "lang=" not in src.lower(): self.out.append(F(1, "<html>", "Quality", "LOW", "Missing lang attribute", "Needed by screen readers.", "Accessibility.", "Add lang=\"en\".", conf=0.9, status="Confirmed"))
        return self.out + run_rules("html", lines)
    def handle_starttag(self, tag, attrs):
        ln, a = self.getpos()[0], dict(attrs); code = self.src_lines[ln-1]
        if tag not in self.VOID: self.stack.append((tag, ln))
        if tag == "img" and "alt" not in a: self.out.append(F(ln, code, "Quality", "LOW", "Image missing alt text", "Accessibility.", "Screen readers can't describe it.", "Add alt.", conf=0.95, status="Confirmed"))
        if any(k.startswith("on") for k in a): self.out.append(F(ln, code, "Security", "LOW", "Inline event handler", "Blocks strict CSP.", "Weakens XSS defenses.", "Use addEventListener.", conf=0.8, status="Suggestion"))
        if tag == "a" and a.get("target") == "_blank" and "noopener" not in a.get("rel", ""): self.out.append(F(ln, code, "Security", "LOW", "target=_blank without rel=noopener", "Opened page can access window.opener.", "Tabnabbing.", "Add rel=\"noopener noreferrer\".", conf=0.8))
    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag: del self.stack[i:]; return

def css_balance(src, lines):
    if src.count("{") != src.count("}"):
        return [F(1, "", "Bug", "HIGH", "Unbalanced braces", f"{src.count('{')} '{{' vs {src.count('}')} '}}'.", "Stylesheet may be ignored.", "Balance the braces.", conf=0.95, status="Confirmed")]
    return []

def java_balance(src, lines):
    if src.count("{") != src.count("}"): return [F(1, "", "Bug", "CRITICAL", "Unbalanced braces", "Brace count mismatch.", "Won't compile.", "Fix braces.", conf=0.9, status="Confirmed")]
    return []

def analyze_code(lang, src):
    lines = src.splitlines()
    if lang == "python": found = PythonAnalyzer().analyze(src, lines)
    elif lang == "html": found = HTMLAnalyzer().analyze(src, lines)
    elif lang in LANG_KEY:
        found = run_rules(lang, lines) + (css_balance(src, lines) if lang == "css" else java_balance(src, lines) if lang == "java" else [])
    else: raise ValueError("Unsupported language")
    return dedupe(found)

def dedupe(findings):
    seen, out = {}, []
    for f in findings:
        k = (f["line_number"], f["title"])
        if k not in seen: seen[k] = f; out.append(f)
        elif f["confidence"] > seen[k]["confidence"]: out[out.index(seen[k])] = seen[k] = f
    return sorted(out, key=lambda f: (-ORDER.index(f["severity"]), f["line_number"] or 0))

def score(findings):
    def s(cats):
        cost = sum(SEV[f["severity"]] * STATUS.get(f["status"], .6) for f in findings if cats is None or f["category"] in cats)
        return max(0, round(100 - cost))
    return dict(overall=s(None), security=s({"Security"}), quality=s({"Quality", "Performance"}),
                maintainability=s({"Maintainability", "Quality"}), reliability=s({"Bug"}))

def label(n): return "Excellent" if n >= 90 else "Good" if n >= 75 else "Needs Improvement" if n >= 60 else "Poor" if n >= 40 else "Critical"
