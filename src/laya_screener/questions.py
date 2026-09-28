"""The questions Laya answers about every email, all in one forward pass.

Written to Laya's documented limits: every `noul` carries explicit criteria
(without them the English checkpoint answers "no" whatever the state), and
`choice` keys are descriptive, never yes/no words.
"""

from __future__ import annotations

from .parse import ParsedEmail

ATTACK_TYPES = {
    "credential_theft": "asks the reader to sign in, verify an account or enter a password through a link",
    "payment_fraud": "asks to pay an invoice, wire money, buy gift cards or change bank details",
    "malware": "pushes the reader to open an attachment or download a file to see a document",
    "ordinary": "an ordinary business, personal or newsletter email with no such request",
}

QUESTIONS = {
    "phishing": {
        "type": "noul",
        "instructions": "Is the email in `body` a phishing or scam attempt to steal money, credentials or personal data?",
        "criteria": {
            "true": "phishing, scam or fraud",
            "false": "a legitimate email",
        },
    },
    "attack_type": {
        "type": "choice",
        "instructions": "What does the email in `body` try to get the reader to do?",
        "criteria": ATTACK_TYPES,
    },
    "pressure": {
        "type": "score",
        "instructions": "How much pressure does the email in `body` put on the reader to act?",
        "criteria": ["no pressure", "a normal deadline", "urgency, threats or a demand for secrecy"],
    },
    "asks_credentials": {
        "type": "noul",
        "instructions": "Does the email in `body` ask the reader to sign in, verify an account or give a password?",
        "criteria": {
            "true": "it asks for a login, a password or an account verification",
            "false": "it asks for no login or password",
        },
    },
    "asks_payment": {
        "type": "noul",
        "instructions": "Does the email in `body` ask for a payment, a wire transfer, gift cards or new bank details?",
        "criteria": {
            "true": "it asks to move money or to change payment details",
            "false": "it asks for no payment and no change of payment details",
        },
    },
}


def email_state(mail: ParsedEmail, max_body_chars: int = 1500) -> dict[str, str]:
    """The state Laya reads. Kept short: the English checkpoint reads about 320 tokens of state."""
    state = {
        "from": f"{mail.sender.name} <{mail.sender.address}>".strip(),
        "subject": mail.subject,
        "body": mail.body[:max_body_chars],
    }
    if mail.attachments:
        state["attachments"] = ", ".join(a.filename for a in mail.attachments)
    return state
