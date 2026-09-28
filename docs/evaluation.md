# Evaluation

Measured with `python eval/evaluate.py` on cuda (laya 0.3.21), over the 18 labeled emails in `samples/` (10 attacks, 8 legitimate; 12 English, 6 Portuguese).
This is a small, hand-made inbox: the numbers show how the parts work together, not how the
screener does on real mail. Measure on your own labeled mail before trusting a threshold.

| Screener | Attacks flagged | Legitimate mail flagged |
|---|---|---|
| Signals only (any high-severity check) | 5/10 | 0/8 |
| Laya only (risk >= 0.5) | 6/10 | 0/8 |
| Combined policy (warn or quarantine) | 9/10 | 1/8 |

Combined policy: 16/18 verdicts exactly as labeled, 0 legitimate emails quarantined.

| Checkpoint | Emails | Median Laya latency |
|---|---|---|
| english | 12 | 62 ms |
| multilingual | 6 | 30 ms |

| Email | Expected | Verdict | Laya risk | Broad phishing answer | Signals |
|---|---|---|---|---|---|
| it-maintenance-window.eml | deliver | deliver | 0.02 | 0.01 | - |
| vendor-invoice-september.eml | deliver | deliver | 0.01 | 0.01 | - |
| colleague-meeting-notes.eml | deliver | deliver | 0.01 | 0.00 | - |
| password-reset-requested.eml | deliver | deliver | 0.40 | 0.39 | - |
| newsletter-cloud-weekly.eml | deliver | deliver | 0.01 | 0.00 | - |
| rh-ferias-comunicado.eml | deliver | deliver | 0.02 | 0.00 | - |
| cliente-segunda-via.eml | deliver | deliver | 0.28 | 0.00 | - |
| lista-parceiros-reply-to.eml | warn | warn | 0.02 | 0.00 | reply_to_mismatch |
| mailbox-full-lookalike.eml | quarantine | quarantine | 0.87 | 0.87 | auth_failed, lookalike_sender, display_name_spoof, link_text_mismatch |
| ceo-wire-transfer.eml | quarantine | quarantine | 0.65 | 0.03 | display_name_spoof |
| vendor-bank-change.eml | quarantine | quarantine | 0.48 | 0.10 | lookalike_sender |
| scanned-document-exe.eml | quarantine | quarantine | 0.21 | 0.21 | auth_failed, double_extension |
| gift-card-request.eml | quarantine | quarantine | 0.56 | 0.56 | - |
| docusign-shortlink.eml | quarantine | warn ✗ | 0.22 | 0.14 | shortened_link |
| banco-conta-bloqueada.eml | quarantine | quarantine | 1.00 | 1.00 | auth_failed, lookalike_sender, lookalike_link |
| diretor-pagamento-urgente.eml | quarantine | quarantine | 0.94 | 0.94 | display_name_spoof |
| boleto-atualizado-html.eml | quarantine | quarantine | 1.00 | 1.00 | auth_failed, risky_attachment |
| proposal-file-share.eml | quarantine | deliver ✗ | 0.15 | 0.15 | - |
