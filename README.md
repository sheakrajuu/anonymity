# Let's Chat Anonymously

Let's Chat Anonymously is a temporary, end-to-end encrypted messaging application. The Node service provides account authentication, temporary invite IDs, room membership, encrypted-message relay, and private storage for encrypted media. It does not have the keys needed to decrypt account private keys, room keys, messages, or media.

## Run locally

Requires Node.js 22.5 or later (for the built-in SQLite module).

```sh
npm install
npm start
```

Open `http://localhost:3000` (the page is `anonymity.html`). Use a secure browser context (localhost or HTTPS) because the application uses the Web Crypto API. Accounts need a unique username and a sign-in password; the server assigns every account a permanent unique ID. The server stores the username for sign-in, a salted scrypt password hash, a public key, and the encrypted private-key bundle. A separate encryption passphrase protects the private key on that device and is never sent to the server. Losing the encryption passphrase means the encrypted conversations cannot be recovered.

Create a temporary conversation with a name and maximum participant count (2–20, including the host). Its name appears in the chat header; the invite ID is revealed only in the share dialog. Invitees sign in to their own accounts and enter the ID. The invite ID is stored only with its temporary room and is replaced if a participant is removed. The host's device creates a new conversation key when invitees join. The invite ID alone cannot read messages or decrypt media. Only the host can end the room. Choosing **Leave conversation** or **End** as the host immediately deletes its server-held messages, media, keys, and invite. Navigating back, signing out, or closing the browser does not end it.

For a permanent one-to-one chat, share your permanent account ID or enter another person's ID in **Settings & contacts**. Each permanent chat has its own end-to-end encryption key. The server stores its encrypted messages and encrypted media until either contact removes the relationship. Blocking a contact prevents both accounts from accessing that permanent chat; contacts and blocked accounts can be managed in settings. Temporary-room members remain anonymous to one another in the interface.

## Render deployment

Upload the project to a GitHub repository and connect that repository in Render using **New → Blueprint**. Include the application source and deployment files: `server.js`, `app.js`, `anonymity.html`, `style.css`, `package.json`, `package-lock.json`, and `render.yaml`. For a maintainable repository, include `README.md`, `THIRD-PARTY-NOTICES.txt`, and `test/` as well. Do not upload `node_modules/`, `data/`, `.test-data/`, or SQLite database/WAL files; Render installs dependencies and the Blueprint creates persistent storage for live account data.

The included `render.yaml` creates a Node web service with a private persistent disk mounted at `/var/data`, runs `npm ci` and `npm start`, and checks `/` for health. Review the Blueprint settings and deploy, then use the generated HTTPS URL. The persistent disk is required: the database and encrypted uploads are not stored in the disposable application filesystem. This single-instance configuration does not support horizontal scaling or multiple service instances sharing the disk.

Configuration:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `DATA_DIR` | `./data` | Directory for the SQLite database and private encrypted-media files |
| `SESSION_TTL_HOURS` | `168` | Maximum session lifetime (1–720 hours) |
| `MAX_MEDIA_BYTES` | `52428800` | Maximum encrypted upload size (50 MiB; capped at 100 MiB) |
| `MAX_ROOM_STORAGE_BYTES` | `536870912` | Maximum encrypted media stored for one conversation (512 MiB; capped at 2 GiB) |

Temporary rooms remain available until the host explicitly chooses **Leave conversation** or **End**. That action immediately deletes the room and its server-held data; ordinary navigation, signing out, or closing the browser does not. A periodic cleanup removes expired legacy records and abandoned upload fragments. The browser enforces the 50 MiB plaintext file limit, video duration, and image metadata stripping before encryption. Images, videos, and other files are encrypted in the browser before upload. The service caps an upload at 50 MiB by default, limits each conversation's stored encrypted media, and limits concurrent uploads and request rates.

Removing a permanent contact deletes the server-held chat and its media for both participants. A copy a recipient already downloaded, captured, or otherwise saved cannot be remotely erased.

## Security and deletion boundaries

- Browser Web Crypto creates a P-256 ECDH identity, encrypts its private key with a passphrase-derived AES-GCM key, and wraps random AES-GCM conversation keys separately for each participant and key epoch. Password authentication is not used to derive decryption keys; the server receives neither the encryption passphrase nor the private key in plaintext.
- Text and media descriptions are AES-GCM encrypted in the browser. Each media file gets a fresh random AES-GCM key; ciphertext is uploaded as `application/octet-stream`. Its decryption key, format, display name, and integrity digest are carried only in the encrypted room message.
- All message and media APIs require an authenticated cookie, current room membership, and a key package for the relevant key epoch. Media endpoints return ciphertext only and do not issue public URLs or object-store credentials. Removing a participant removes their key packages, rotates the invite ID, and requires the owner to distribute a fresh room key to remaining participants before sending again.
- Ending a temporary room removes its media files and database rows immediately. Removing a permanent contact removes the permanent chat data. Deleting database rows and unlinking files prevents normal application/API retrieval, but does not guarantee immediate physical erasure from storage media, SQLite WAL files, provider infrastructure, or provider-level snapshots/forensic recovery. Render disk costs, availability, and any platform-level retention depend on the selected Render plan and current platform policies; verify those policies before handling regulated data.
- Deletion cannot remove a copy that a recipient already downloaded, captured, or otherwise saved. The app cannot remotely erase independent copies.
- The service cannot validate plaintext media format or duration without breaking end-to-end confidentiality. Client-side checks improve UX but a modified client can bypass them; the server still enforces encrypted-byte and request-rate limits.

Run the focused backend checks with `npm test`.

## Icons

The interface embeds selected open-source Lucide SVG icons locally, so pages do not make third-party icon requests. Licensing notices are in [THIRD-PARTY-NOTICES.txt](./THIRD-PARTY-NOTICES.txt).
