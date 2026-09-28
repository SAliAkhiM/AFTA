# پلتفرم جامع ارزیابی امنیتی و صدور انطباق افتا (AFTA Security Platform)

سامانه یکپارچه ممیزی امنیتی نرم‌افزار و ارزیابی انطباق با **الزامات امنیتی افتا (فضای تبادل اطلاعات)**. این سامانه با تجمیع و تحلیل یافته‌های آزمون‌های ایستا (SAST)، آزمون‌های پویا (DAST) و آزمون ترکیب نرم‌افزار (SCA)، گزارش‌های رسمی و کارنامه انطباق تولید می‌کند.

---

## 🏗️ ساختار ماژولار پروژه

```text
AFTA/
├── common/                     # قراردادهای تبادل داده مشترک و مدل‌های Pydantic
│   ├── models.py               # ساختار استاندارد یافته‌ها (Unified Data Contract)
│   └── __init__.py
│
├── module3_sca/                # ماژول ۳: تحلیل وابستگی‌ها و تولید SBOM
│   ├── analyzers/              # پارسرهای فایل‌های مانیفست (requirements.txt, package.json و ...)
│   ├── sbom/                   # تولید استاندارد CycloneDX v1.5 JSON
│   ├── vulnerability/          # استعلام OSV، امتیاز EPSS و ماتریس ریسک ترکیبی
│   ├── sca_engine.py           # هسته هماهنگ‌کننده SCA
│   └── cli.py                  # واسط خط فرمان اسکنر SCA
│
├── module4_aggregator/         # ماژول ۴: تجمیع، همبستگی و ممیزی افتا
│   ├── ingestion/              # سرویس دریافت و اعتبارسنجی خروجی اسکنرها
│   ├── correlation/            # الگوریتم‌های Deduplication و تأیید متقابل دوگانه (SAST + DAST)
│   ├── afta_compliance/        # چک‌لیست الزامات افتا و موتور ارزیابی Pass/Fail
│   ├── reporting/              # موتور تولید گزارش ممیزی افتا (قالب فارسی راست‌چین)
│   └── cli.py                  # واسط خط فرمان تجمیع و صدور گزارش
│
├── samples/                    # نمونه خروجی‌ها و تارگت‌های آزمایشی
│   ├── sast_sample.json        # خروجی نمونه ماژول ۱ (Semgrep/Bandit/Gitleaks)
│   ├── dast_sample.json        # خروجی نمونه ماژول ۲ (OWASP ZAP)
│   └── vulnerable_app/         # پروژه تستی حاوی کتابخانه‌های آسیب‌پذیر
│
└── tests/                      # تست‌های خودکار واحد و یکپارچه‌سازی
```

---

## 🚀 نصب و راه‌اندازی سریع

### ۱. نصب وابستگی‌ها
```bash
pip install -r requirements.txt
```

### ۲. اجرای ماژول ۳ (SCA Scanner)
برای استخراج وابستگی‌ها، تولید SBOM استاندارد CycloneDX و کشف آسیب‌پذیری‌ها:
```bash
python -m module3_sca.cli samples/vulnerable_app --output sca_findings.json --sbom sbom.json
```

### ۳. اجرای ماژول ۴ (Aggregator & AFTA Report)
برای تجمیع خروجی ماژول‌های SAST، DAST و SCA و صدور گزارش رسمی انطباق با افتا:
```bash
python -m module4_aggregator.cli \
  --sast samples/sast_sample.json \
  --dast samples/dast_sample.json \
  --sca sca_findings.json \
  --target-name "سامانه پرتال بیمارستانی" \
  --output afta_compliance_report.html
```

---

## 🛡️ نوآوری‌های پیاده‌سازی شده

1. **تولید خودکار SBOM بر مبنای CycloneDX v1.5:**
   خروجی استاندارد سازگار با ابزارهای جهانی با شناسه یکتای PURL.
2. **اولویت‌بندی هوشمند با ماتریس ریسک توأم CVSS و EPSS:**
   ترکیب شدت تئوریک آسیب‌پذیری با احتمال اکسپلویت واقعی در سطح اینترنت از طریق FIRST.org API.
3. **تأیید متقابل دوگانه (Cross-Verification):**
   شناسایی خودکار مواردی که هم توسط تحلیل ایستا (کد منبع) و هم توسط آزمون نفوذ پویا (DAST) اثبات شده‌اند.
4. **کارنامه رسمی انطباق افتا (Compliance Scorecard):**
   نگاشت دقیق ضعف‌های امنیتی به حوزه‌های ۸‌گانه چک‌لیست امنیت برنامه‌های کاربردی افتا همراه با گزارش حرفه‌ای HTML/PDF با زبان فارسی.
