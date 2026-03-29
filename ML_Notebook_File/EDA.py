# ============================================================
# SECTION 3 — EXPLORATORY DATA ANALYSIS (EDA)
# ============================================================

# ── 3.1 Label distribution — Dataset 1 ────────────────────
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

email_df['label'].value_counts().plot(
    kind='bar',
    ax=axes[0],
    color=['#2ecc71', '#e74c3c'],
    edgecolor='black',
    width=0.5
)
axes[0].set_title('Dataset 1 — Email Label Distribution', fontsize=13)
axes[0].set_xlabel('Label (0 = Legitimate, 1 = Phishing)')
axes[0].set_ylabel('Count')
axes[0].set_xticklabels(['Legitimate (0)', 'Phishing (1)'], rotation=0)
for p in axes[0].patches:
    axes[0].annotate(f'{int(p.get_height()):,}',
                     (p.get_x() + p.get_width() / 2, p.get_height()),
                     ha='center', va='bottom', fontsize=11)

# ── 3.2 Label distribution — Dataset 2 ────────────────────
url_df['label'].value_counts().plot(
    kind='bar',
    ax=axes[1],
    color=['#2ecc71', '#e74c3c'],
    edgecolor='black',
    width=0.5
)
axes[1].set_title('Dataset 2 — URL Label Distribution', fontsize=13)
axes[1].set_xlabel('Label (0 = Legitimate, 1 = Phishing)')
axes[1].set_ylabel('Count')
axes[1].set_xticklabels(['Legitimate (0)', 'Phishing (1)'], rotation=0)
for p in axes[1].patches:
    axes[1].annotate(f'{int(p.get_height()):,}',
                     (p.get_x() + p.get_width() / 2, p.get_height()),
                     ha='center', va='bottom', fontsize=11)

plt.tight_layout()
plt.savefig('label_distribution.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.1 — Label distribution plotted")

# ── 3.2 Rows per source ───────────────────────────────────
plt.figure(figsize=(10, 5))
source_counts = email_df['source'].value_counts()
source_counts.plot(
    kind='bar',
    color='#3498db',
    edgecolor='black',
    width=0.6
)
plt.title('Dataset 1 — Rows per Source File', fontsize=13)
plt.xlabel('Source')
plt.ylabel('Row Count')
plt.xticks(rotation=30, ha='right')
for i, v in enumerate(source_counts):
    plt.text(i, v + 300, f'{v:,}', ha='center', fontsize=10)
plt.tight_layout()
plt.savefig('rows_per_source.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.2 — Source distribution plotted")

# ── 3.3 Phishing vs Legitimate per source ─────────────────
source_label = email_df.groupby(['source', 'label']).size().unstack(fill_value=0)
source_label.columns = ['Legitimate', 'Phishing']
source_label.plot(
    kind='bar',
    figsize=(12, 5),
    color=['#2ecc71', '#e74c3c'],
    edgecolor='black',
    width=0.6
)
plt.title('Dataset 1 — Phishing vs Legitimate per Source', fontsize=13)
plt.xlabel('Source')
plt.ylabel('Count')
plt.xticks(rotation=30, ha='right')
plt.legend(title='Label')
plt.tight_layout()
plt.savefig('phishing_vs_legit_per_source.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.3 — Per-source label breakdown plotted")

# ── 3.4 Email body length distribution ────────────────────
email_df['body_length'] = email_df['body'].fillna('').apply(len)

plt.figure(figsize=(12, 5))
for label, color, name in [(0, '#2ecc71', 'Legitimate'), (1, '#e74c3c', 'Phishing')]:
    subset = email_df[email_df['label'] == label]['body_length']
    subset.clip(upper=5000).plot(
        kind='hist',
        bins=60,
        alpha=0.6,
        color=color,
        label=name,
        edgecolor='black'
    )
plt.title('Email Body Length Distribution (clipped at 5000 chars)', fontsize=13)
plt.xlabel('Body Length (characters)')
plt.ylabel('Frequency')
plt.legend()
plt.tight_layout()
plt.savefig('body_length_distribution.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.4 — Body length distribution plotted")

# ── 3.5 Subject length distribution ───────────────────────
email_df['subject_length'] = email_df['subject'].fillna('').apply(len)

plt.figure(figsize=(12, 5))
for label, color, name in [(0, '#2ecc71', 'Legitimate'), (1, '#e74c3c', 'Phishing')]:
    subset = email_df[email_df['label'] == label]['subject_length']
    subset.clip(upper=200).plot(
        kind='hist',
        bins=50,
        alpha=0.6,
        color=color,
        label=name,
        edgecolor='black'
    )
plt.title('Email Subject Length Distribution (clipped at 200 chars)', fontsize=13)
plt.xlabel('Subject Length (characters)')
plt.ylabel('Frequency')
plt.legend()
plt.tight_layout()
plt.savefig('subject_length_distribution.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.5 — Subject length distribution plotted")

# ── 3.6 URL feature correlations — Dataset 2 ──────────────
plt.figure(figsize=(20, 16))
corr = url_df.drop(columns=['label']).corr()
sns.heatmap(
    corr,
    cmap='coolwarm',
    center=0,
    linewidths=0.3,
    annot=False,
    square=True
)
plt.title('Dataset 2 — URL Feature Correlation Heatmap', fontsize=13)
plt.tight_layout()
plt.savefig('url_correlation_heatmap.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.6 — URL feature correlation heatmap plotted")

# ── 3.7 Top URL features correlated with label ────────────
label_corr = url_df.corr()['label'].drop('label').abs().sort_values(ascending=False)

plt.figure(figsize=(12, 7))
label_corr.head(20).plot(
    kind='bar',
    color='#9b59b6',
    edgecolor='black',
    width=0.6
)
plt.title('Dataset 2 — Top 20 URL Features Correlated with Label', fontsize=13)
plt.xlabel('Feature')
plt.ylabel('Absolute Correlation with Label')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig('top_url_features.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.7 — Top URL feature correlations plotted")

# ── 3.8 Missing values heatmap — Dataset 1 ────────────────
plt.figure(figsize=(10, 5))
missing = email_df[['sender', 'receiver', 'date', 'subject', 'body', 'urls']].isnull()
sns.heatmap(
    missing,
    cbar=False,
    cmap='Reds',
    yticklabels=False
)
plt.title('Dataset 1 — Missing Values Heatmap', fontsize=13)
plt.xlabel('Column')
plt.tight_layout()
plt.savefig('missing_values_heatmap.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.8 — Missing values heatmap plotted")

# ── 3.9 Phishing keyword frequency in email body ──────────
PHISHING_KEYWORDS = [
    'click', 'verify', 'account', 'password', 'urgent',
    'bank', 'login', 'update', 'confirm', 'secure',
    'winner', 'prize', 'free', 'offer', 'limited'
]

keyword_phishing    = {}
keyword_legitimate  = {}

phishing_bodies    = email_df[email_df['label'] == 1]['body'].fillna('').str.lower()
legitimate_bodies  = email_df[email_df['label'] == 0]['body'].fillna('').str.lower()

for kw in PHISHING_KEYWORDS:
    keyword_phishing[kw]   = phishing_bodies.str.contains(kw).sum()
    keyword_legitimate[kw] = legitimate_bodies.str.contains(kw).sum()

kw_df = pd.DataFrame({
    'Phishing'   : keyword_phishing,
    'Legitimate' : keyword_legitimate
})

kw_df.plot(
    kind='bar',
    figsize=(14, 6),
    color=['#e74c3c', '#2ecc71'],
    edgecolor='black',
    width=0.6
)
plt.title('Dataset 1 — Phishing Keyword Frequency in Email Body', fontsize=13)
plt.xlabel('Keyword')
plt.ylabel('Occurrences')
plt.xticks(rotation=30, ha='right')
plt.legend(title='Label')
plt.tight_layout()
plt.savefig('keyword_frequency.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.9 — Keyword frequency plotted")

# ── 3.10 URL feature distributions — top 6 features ───────
top_features = label_corr.head(6).index.tolist()

fig, axes = plt.subplots(2, 3, figsize=(16, 10))
axes = axes.flatten()

for i, feature in enumerate(top_features):
    for label, color, name in [(0, '#2ecc71', 'Legitimate'), (1, '#e74c3c', 'Phishing')]:
        subset = url_df[url_df['label'] == label][feature]
        axes[i].hist(
            subset,
            bins=30,
            alpha=0.6,
            color=color,
            label=name,
            edgecolor='black'
        )
    axes[i].set_title(f'{feature}', fontsize=11)
    axes[i].set_xlabel('Value')
    axes[i].set_ylabel('Frequency')
    axes[i].legend()

plt.suptitle('Dataset 2 — Top 6 URL Feature Distributions by Label', fontsize=13, y=1.02)
plt.tight_layout()
plt.savefig('url_feature_distributions.png', dpi=150, bbox_inches='tight')
plt.show()
print("3.10 — URL feature distributions plotted")

# ── 3.11 Summary stats ────────────────────────────────────
print("\n")
print("=" * 55)
print("EDA SUMMARY")
print("=" * 55)
print(f"Total email samples       : {email_df.shape[0]:,}")
print(f"Phishing emails           : {(email_df['label']==1).sum():,}")
print(f"Legitimate emails         : {(email_df['label']==0).sum():,}")
print(f"Avg body length           : {email_df['body_length'].mean():.0f} chars")
print(f"Avg subject length        : {email_df['subject_length'].mean():.0f} chars")
print(f"Phishing avg body length  : {email_df[email_df['label']==1]['body_length'].mean():.0f} chars")
print(f"Legitimate avg body length: {email_df[email_df['label']==0]['body_length'].mean():.0f} chars")
print(f"\nMissing values in email_df:")
print(email_df.isnull().sum())
print(f"\nTop 5 URL features by correlation with label:")
print(label_corr.head(5).to_string())
print(f"\nMost frequent phishing keyword : {max(keyword_phishing, key=keyword_phishing.get)}")
print(f"Most frequent legit keyword    : {max(keyword_legitimate, key=keyword_legitimate.get)}")
print(f"\nEDA complete — 10 sections done")
