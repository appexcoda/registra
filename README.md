# Registra

A self-hosted REST API for indexing, searching, and managing Guitar Pro (GP/GPX) and PDF music sheet files.  
Built with Go and SQLite FTS5 for fast full-text search.

## Features

- **Full-text search** across file names, artists, titles, and metadata
- **Automatic indexing** with periodic scanning
- **Concurrent metadata extraction** from Guitar Pro files
- **File uploads** with duplicate detection (content hash-based)
- **RESTful API** with API key authentication
- **HTTPS by default** with automatic self-signed certificate generation
- **TOFU security model** for mobile clients
- **QR code generation** for easy mobile app setup
- **Rate limiting** per IP address
- **Structured logging** with request IDs

## Architecture

- **Read-only indexed directories** (`FILES_PATH`): Registra scans and indexes these directories but never modifies them
- **Writable upload directories** (`UPLOAD_PATH_GP`, `UPLOAD_PATH_PDF`): Files uploaded via API are stored here
- **SQLite database** with FTS5 virtual tables for search
- **Batched writes** for efficient indexing
- **Hash-based deduplication** prevents identical files from being indexed multiple times

## Requirements

- Go 1.21+ (for building from source)
- Linux, macOS, or Windows
- Network-accessible filesystem for indexed directories

### Building from Source

```bash
git clone https://github.com/appexcoda/registra.git
cd registra
go build -o registra
./registra
```
## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FILES_PATH` | Yes | - | Comma or semicolon-separated list of directories to index (read-only) |
| `UPLOAD_PATH_GP` | Yes | - | Directory for uploaded GP/GPX files (writable) |
| `UPLOAD_PATH_PDF` | Yes | - | Directory for uploaded PDF files (writable) |
| `DB_PATH` | Yes | - | SQLite database file path |
| `CERTS_PATH` | Yes | - | SSL certificates directory; api_key.txt |
| `PORT` | No | `8443` | HTTPS server port |
| `LOG_LEVEL` | No | `info` | Logging level: `debug`, `info`, `warn`, `error` |
| `API_KEY` | No | Auto-generated | API authentication key (see below) |

### Example Configuration

```bash
export FILES_PATH="/media/music,/backup/sheets"
export UPLOAD_PATH_GP="/var/registra/uploads/gp"
export UPLOAD_PATH_PDF="/var/registra/uploads/pdf"
export DB_PATH="/var/registra/data/registra.db"
export CERTS_PATH="/var/registra/certs"
export PORT=8443
export LOG_LEVEL=info
export API_KEY=your-secret-key-here

./registra
```

### Windows

```cmd
set FILES_PATH=C:\Music
set UPLOAD_PATH_GP=C:\Registra\uploads\gp
set UPLOAD_PATH_PDF=C:\Registra\uploads\pdf
set DB_PATH=C:\Registra\data\registra.db
set CERTS_PATH=C:\Registra\certs
set PORT=8443

registra.exe
```

## API Key Management

Registra uses API keys for authentication. The key is determined in the following order:

1. **Environment variable**: If `API_KEY` is set, it will be used
2. **File**: If `api_key.txt` exists in the certs directory (`CERTS_PATH`), it will be loaded
3. **Auto-generated**: If neither exists, a new 256-bit key is generated and saved to `CERTS_PATH\api_key.txt`

The API key is displayed in the console on startup and encoded in the QR code.

### Using the API Key

Include the API key in requests using either header:

```bash
# X-API-Key header (recommended)
curl -H "X-API-Key: your-api-key" https://192.168.1.100:8443/api/v1/health

# Authorization header
curl -H "Authorization: Bearer your-api-key" https://192.168.1.100:8443/api/v1/health
```

## SSL/TLS and Certificate Management

Registra automatically generates self-signed SSL certificates on first startup. Certificates are valid for 10 years and include the server's network IP address.

### Certificate Location

Certificates are stored in `CERTS_PATH`:
- `cert.pem`: SSL certificate
- `key.pem`: Private key

### Trust On First Use (TOFU)

Registra implements a Trust On First Use security model for mobile clients:

1. **First connection**: Client sees the certificate fingerprint and chooses to accept or reject
2. **Fingerprint stored**: Accepted fingerprint is stored in the client app
3. **Subsequent connections**: Client verifies the server certificate matches the stored fingerprint
4. **Changed certificate**: If the fingerprint changes, the client warns about a potential MITM attack

This approach is suitable for self-hosted environments where traditional CA-signed certificates are impractical.

### Regenerating Certificates

Delete certificates from `CERTS_PATH` directory and restart:

```bash
rm -rf ./certs/*
./registra
```

Clients will need to re-accept the new certificate fingerprint.

## Android App Integration [ExCoda](https://github.com/appexcoda/excoda)

Registra is designed to work seamlessly with the ExCoda Android app for viewing and managing music sheets.

### QR Code Setup

On startup, Registra generates a QR code in the console containing:

```json
{
  "url": "https://192.168.1.100:8443",
  "key": "your-api-key",
  "v": 1
}
```

**Setup flow:**

1. Start Registra server
2. Scan the QR code from the console using ExCoda
3. App automatically configures the server URL and API key
4. On connectivity check app prompts to accept the SSL certificate fingerprint (TOFU)
5. Fingerprint is stored for future connections

### Certificate Trust Flow

**First connection:**
```
[User] → Taps "Scan QR" in ExCoda Registra Settings and scans QR from Registra console
[User] → Taps "Check"
[ExCoda] → Connects to Registra
[Registra] → Presents self-signed certificate
[ExCoda] → Shows certificate details:
                - Host: 192.168.1.100
                - Fingerprint: A1:B2:C3:D4:...
                - Valid from: 2025-01-01
                - Valid to: 2035-01-01
[User] → Taps "Accept"
[ExCoda] → Stores fingerprint
```

**Subsequent connections:**
```
[ExCoda] → Connects to Registra
[Registra] → Presents certificate
[ExCoda] → Verifies fingerprint matches stored value
[ExCoda] → Connection established ✓
```

**Certificate changed:**
```
[ExCoda] → Connects to Registra
[Registra] → Presents certificate (new fingerprint)
[ExCoda] → ⚠️ CERTIFICATE CHANGED ⚠️
[ExCoda] → Shows warning about potential MITM attack
[User] → Repeats steps from "First connection"
```

## API Reference

All endpoints require authentication via `X-API-Key` or `Authorization: Bearer <key>` header.

### Health Check

```http
GET /api/v1/health
```

**Response:**
```json
{
  "status": "ok"
}
```

### Search

```http
GET /api/v1/search?text=bach&file_type=gp&page=1&page_size=20
```

**Query Parameters:**
- `text` - Search across file name, artist, title, subtitle
- `artist` - Filter by artist
- `title` - Filter by title
- `file_type` - Filter by type: `gp` (includes gpx) or `pdf`
- `page` - Page number (default: 1)
- `page_size` - Results per page (default: 20, max: 100)

At least one search parameter (`text`, `artist`, or `title`) is required.

**Response:**
```json
{
  "results": [
    {
      "ID": 42,
      "FileName": "BWV147.gp",
      "FilePath": "/files/bach/BWV147.gp",
      "FileType": "gp",
      "Artist": "bach",
      "Title": "Jesu Joy of Mans Desiring Johann Sebastian Bach",
      "Album": "bach",
      "FileSize": 45678,
      "IndexedAt": "2025-11-16T12:00:00Z",
      "ModifiedAt": "2024-01-15T10:30:00Z",
      "IsUploaded": false
    }
  ],
  "total": 42,
  "returned": 1,
  "page": 1,
  "page_size": 20,
  "total_pages": 3
}
```

The `IsUploaded` field indicates whether the file is in an upload directory (`true`) or an indexed directory (`false`).

### Upload File

```http
POST /api/v1/files
Content-Type: multipart/form-data

file: <binary data>
```

**Success Response (201):**
```json
{
  "message": "File uploaded successfully",
  "filename": "song.gp",
  "path": "/uploads/gp"
}
```

**Conflict Response (409) - File name exists:**
```json
{
  "error": "File with this name already exists",
  "existing_file": {
    "id": 15,
    "filename": "song.gp"
  }
}
```

**Conflict Response (409) - Duplicate content:**
```json
{
  "error": "Duplicate file: identical content already exists as 'existing.gp'"
}
```

**Upload behavior:**
- Files are routed to `UPLOAD_PATH_GP` or `UPLOAD_PATH_PDF` based on extension
- Content hash is calculated and checked against existing files
- If identical content exists anywhere, upload is rejected
- If file name exists in the same upload folder, returns conflict with file ID
- Client can delete the existing file and retry upload

### Download File

```http
GET /api/v1/files/{id}
```

Downloads the file with the given ID. Response includes `Content-Disposition` header with the original filename.

### Delete File

```http
DELETE /api/v1/files/{id}
```

Deletes the file with the given ID from both filesystem and database. Files in indexed directories (`FILES_PATH`) can be deleted via API but will be re-indexed on the next scan.

**Response:**
```json
{
  "message": "File deleted successfully"
}
```

### Trigger Scan

```http
POST /api/v1/scan
```

Manually triggers a full `FILES_PATH` scan. Scanning happens asynchronously.

**Response (202):**
```json
{
  "message": "Scan initiated"
}
```

### Statistics

```http
GET /api/v1/stats
```

**Response:**
```json
{
  "total_files": 1234,
  "total_size_bytes": 567890123,
  "total_size_gb": 0.53,
  "by_type": {
    "gp": 800,
    "gpx": 234,
    "pdf": 200
  },
  "indexer": {
    "queue_depth": 0,
    "files_indexed": 1234,
    "files_deleted": 56,
    "indexing_errors": 2,
    "batches_written": 45,
    "queue_capacity": 1000
  }
}
```

## Client Examples

### cURL

```bash
API_KEY="your-api-key"
HOST="https://192.168.1.100:8443"

# Search
curl -k -H "X-API-Key: $API_KEY" \
  "$HOST/api/v1/search?text=bach&file_type=gp"

# Upload
curl -k -H "X-API-Key: $API_KEY" \
  -F "file=@/path/to/song.gp" \
  "$HOST/api/v1/files"

# Download
curl -k -H "X-API-Key: $API_KEY" \
  "$HOST/api/v1/files/42" -o song.gp

# Delete
curl -k -X DELETE -H "X-API-Key: $API_KEY" \
  "$HOST/api/v1/files/42"
```

Note: `-k` flag disables certificate verification for self-signed certificates.

## Performance

- **Concurrent indexing**: Configurable worker pool (default: 10 threads)
- **Batch writes**: Groups database operations into batches of 100 for efficiency
- **FTS5 search**: Full-text search with SQLite FTS5, falls back to LIKE queries if needed
- **Rate limiting**: 100 requests/second per IP, burst of 10
- **Connection pooling**: 10 max open connections, 5 idle
- **Periodic scanning**: Runs every 1 minute to detect filesystem changes

## Logging

Logs are written to stdout with structured format:

```
[INFO] [abc12345] GET /api/v1/search from 192.168.1.50
[INFO] [abc12345] Search page=1 pageSize=20 returned=15 totalResults=45 text='bach'
[INFO] [abc12345] GET /api/v1/search - 200 in 24ms
```

Request IDs (`abc12345`) correlate all log entries for a single request.

### Log Levels

- `debug`: Detailed information including skipped duplicates
- `info`: General operational messages (default)
- `warn`: Warnings about non-critical issues
- `error`: Errors that need attention

## Troubleshooting

### Port already in use

```
Server error: listen tcp :8443: bind: address already in use
```

Change the port:
```bash
export PORT=8444
./registra
```

### Permission denied on upload directories

```
UPLOAD_PATH_GP directory /uploads/gp is not writable
```

Ensure the directories exist and are writable:
```bash
mkdir -p /uploads/gp /uploads/pdf
chmod 755 /uploads/gp /uploads/pdf
```

### Files not appearing in search

- Check logs for indexing errors
- Verify file paths are under `FILES_PATH` or upload directories
- Manually trigger a scan: `POST /api/v1/scan`
- Check file extensions are `.gp`, `.gpx`, or `.pdf`

### Database locked errors

```
database is locked
```

Increase busy timeout or reduce concurrent operations. SQLite uses WAL mode for better concurrency.

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Security Considerations

- **Self-signed certificates**: Suitable for local networks and self-hosted environments. For internet-facing deployments, consider using Let's Encrypt or another CA.
- **API key storage**: Store API keys securely. Avoid committing `api_key.txt` to version control.
- **TOFU limitations**: Protects against passive eavesdropping but vulnerable to active MITM on first connection. Verify certificate fingerprints out-of-band when possible.
- **File uploads**: Registra validates file extensions and extracts metadata, but does not perform deep file content validation. Only allow uploads from trusted users.
- **Rate limiting**: Default rate limits (100 req/s per IP) may need adjustment for production use.

## Related Projects

- **[ExCoda](https://github.com/appexcoda/excoda)**: Android app for viewing Guitar Pro, MusicXML and PDF music sheets, integrates with Registra for cloud-based library management.