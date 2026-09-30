# Privacy-Bounded User Context

## Clipboard

`clipboard_metadata` records whether text is available and its length/format metadata. It never returns, stores, hashes, or transmits clipboard contents.

## Browser history

`browser_history_metadata` inspects local browser History databases when accessible. It returns browser/profile metadata, a redacted domain hash, and visit timestamps. URLs and page titles are not returned.

## Cookies

`browser_cookie_metadata` returns browser/profile, redacted host hashes, expiry, Secure, and HttpOnly flags. Cookie values are never returned and cookie decryption is not performed.

These collectors are read-only and bounded. Their purpose is contextual forensic evidence, not credential or session-token extraction.
