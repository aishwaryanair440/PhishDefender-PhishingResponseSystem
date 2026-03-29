# ============================================================
# SECTION 6 — TRAIN-TEST SPLIT
# ============================================================

from sklearn.model_selection import train_test_split

# ──────────────────────────────────────────────────────────
# 6.1 EMAIL DATASET SPLIT
# ──────────────────────────────────────────────────────────

print("=" * 55)
print("6.1 — Email Dataset Train-Test Split")
print("=" * 55)

# stratify=y_email ensures label ratio is preserved
# in both train and test sets
# random_state=42 for reproducibility
X_email_train, X_email_test, y_email_train, y_email_test = train_test_split(
    X_email,
    y_email,
    test_size    = 0.2,
    random_state = 42,
    stratify     = y_email
)

print(f"Total samples          : {X_email.shape[0]:,}")
print(f"Training samples       : {X_email_train.shape[0]:,}")
print(f"Testing samples        : {X_email_test.shape[0]:,}")
print(f"Feature count          : {X_email_train.shape[1]:,}")
print(f"\nTraining label split:")
unique, counts = np.unique(y_email_train, return_counts=True)
for u, c in zip(unique, counts):
    print(f"  Label {u} : {c:,} ({c/len(y_email_train)*100:.1f}%)")
print(f"\nTesting label split:")
unique, counts = np.unique(y_email_test, return_counts=True)
for u, c in zip(unique, counts):
    print(f"  Label {u} : {c:,} ({c/len(y_email_test)*100:.1f}%)")

# ──────────────────────────────────────────────────────────
# 6.2 URL DATASET SPLIT
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("6.2 — URL Dataset Train-Test Split")
print("=" * 55)

X_url_train, X_url_test, y_url_train, y_url_test = train_test_split(
    url_fe,
    y_url,
    test_size    = 0.2,
    random_state = 42,
    stratify     = y_url
)

print(f"Total samples          : {url_fe.shape[0]:,}")
print(f"Training samples       : {X_url_train.shape[0]:,}")
print(f"Testing samples        : {X_url_test.shape[0]:,}")
print(f"Feature count          : {X_url_train.shape[1]:,}")
print(f"\nTraining label split:")
unique, counts = np.unique(y_url_train, return_counts=True)
for u, c in zip(unique, counts):
    print(f"  Label {u} : {c:,} ({c/len(y_url_train)*100:.1f}%)")
print(f"\nTesting label split:")
unique, counts = np.unique(y_url_test, return_counts=True)
for u, c in zip(unique, counts):
    print(f"  Label {u} : {c:,} ({c/len(y_url_test)*100:.1f}%)")

# ──────────────────────────────────────────────────────────
# 6.3 VISUALIZE SPLIT PROPORTIONS
# ──────────────────────────────────────────────────────────

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Email split visualization
email_split_data = {
    'Train' : X_email_train.shape[0],
    'Test'  : X_email_test.shape[0]
}
axes[0].pie(
    email_split_data.values(),
    labels    = [f"{k}\n{v:,}" for k, v in email_split_data.items()],
    colors    = ['#3498db', '#e74c3c'],
    autopct   = '%1.1f%%',
    startangle= 90,
    textprops = {'fontsize': 12}
)
axes[0].set_title('Email Dataset — Train/Test Split', fontsize=13)

# URL split visualization
url_split_data = {
    'Train' : X_url_train.shape[0],
    'Test'  : X_url_test.shape[0]
}
axes[1].pie(
    url_split_data.values(),
    labels    = [f"{k}\n{v:,}" for k, v in url_split_data.items()],
    colors    = ['#3498db', '#e74c3c'],
    autopct   = '%1.1f%%',
    startangle= 90,
    textprops = {'fontsize': 12}
)
axes[1].set_title('URL Dataset — Train/Test Split', fontsize=13)

plt.tight_layout()
plt.savefig('train_test_split.png', dpi=150, bbox_inches='tight')
plt.show()
print("6.3 — Train/test split pie charts plotted")

# ──────────────────────────────────────────────────────────
# 6.4 SPLIT SUMMARY
# ──────────────────────────────────────────────────────────

print("\n")
print("=" * 55)
print("6.4 — Split Summary")
print("=" * 55)
print(f"Email dataset")
print(f"  X_email_train : {X_email_train.shape}")
print(f"  X_email_test  : {X_email_test.shape}")
print(f"  y_email_train : {y_email_train.shape}")
print(f"  y_email_test  : {y_email_test.shape}")
print(f"\nURL dataset")
print(f"  X_url_train   : {X_url_train.shape}")
print(f"  X_url_test    : {X_url_test.shape}")
print(f"  y_url_train   : {y_url_train.shape}")
print(f"  y_url_test    : {y_url_test.shape}")
print(f"\nOutputs ready for Section 7:")
print(f"  X_email_train, X_email_test, y_email_train, y_email_test")
print(f"  X_url_train, X_url_test, y_url_train, y_url_test")
