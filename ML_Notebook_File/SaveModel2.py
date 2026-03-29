# ============================================================
# SECTION 9.11 — ZIP ALL OUTPUT FILES
# ============================================================

import zipfile
import os

print("=" * 55)
print("9.11 — Zipping All Model Files")
print("=" * 55)

ZIP_PATH = '/kaggle/working/phishing_models.zip'

with zipfile.ZipFile(ZIP_PATH, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for fname in os.listdir(SAVE_DIR):
        fpath = os.path.join(SAVE_DIR, fname)
        zipf.write(fpath, arcname=fname)
        print(f"  Added : {fname}")

zip_size = os.path.getsize(ZIP_PATH)
print(f"\nZip file created   : {ZIP_PATH}")
print(f"Zip file size      : {zip_size/1024/1024:.2f} MB")
print(f"\nDownload from Kaggle output panel:")
print(f"  /kaggle/working/phishing_models.zip")
