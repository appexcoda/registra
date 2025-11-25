package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	dbMaxOpenConns    = 10 
	dbMaxIdleConns    = 5
	dbConnMaxLifetime = 5 * time.Minute
	dbConnMaxIdleTime = 30 * time.Second
	dbBusyTimeout     = 5000
	defaultPageSize   = 20
	maxPageSize       = 100
)

type DB struct {
	conn *sql.DB
}

func NewDB(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}

	if _, err := conn.Exec(fmt.Sprintf("PRAGMA busy_timeout=%d", dbBusyTimeout)); err != nil {
		return nil, err
	}

	conn.SetMaxOpenConns(dbMaxOpenConns)
	conn.SetMaxIdleConns(dbMaxIdleConns)
	conn.SetConnMaxLifetime(dbConnMaxLifetime)
	conn.SetConnMaxIdleTime(dbConnMaxIdleTime)

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *DB) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT UNIQUE NOT NULL,
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    artist TEXT,
    title TEXT,
    subtitle TEXT,
    album TEXT,
    file_hash TEXT,
    file_size INTEGER NOT NULL,
    indexed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    modified_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_file_type ON files(file_type);
CREATE INDEX IF NOT EXISTS idx_artist ON files(artist);
CREATE INDEX IF NOT EXISTS idx_title ON files(title);
CREATE INDEX IF NOT EXISTS idx_hash ON files(file_hash);
CREATE INDEX IF NOT EXISTS idx_modified ON files(modified_at);

CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
    file_name,
    artist,
    title,
    subtitle,
    content=files,
    content_rowid=id
);

CREATE TRIGGER IF NOT EXISTS files_ai AFTER INSERT ON files BEGIN
    INSERT INTO files_fts(rowid, file_name, artist, title, subtitle)
    VALUES (new.id, new.file_name, new.artist, new.title, new.subtitle);
END;

CREATE TRIGGER IF NOT EXISTS files_ad AFTER DELETE ON files BEGIN
    DELETE FROM files_fts WHERE rowid = old.id;
END;

CREATE TRIGGER IF NOT EXISTS files_au AFTER UPDATE ON files BEGIN
    UPDATE files_fts
    SET file_name=new.file_name, artist=new.artist, title=new.title, subtitle=new.subtitle
    WHERE rowid=new.id;
END;
`

	_, err := db.conn.Exec(schema)
	return err
}

func (db *DB) GetAllFiles() ([]*FileMetadata, error) {
	rows, err := db.conn.Query(`
		SELECT id, file_path, file_name, file_type, artist, title, subtitle, album,
		       file_hash, file_size, indexed_at, modified_at
		FROM files
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*FileMetadata
	for rows.Next() {
		f, err := scanFileMetadata(rows)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}

	return files, rows.Err()
}

func (db *DB) GetFileByPath(path string) (*FileMetadata, error) {
	row := db.conn.QueryRow(`
		SELECT id, file_path, file_name, file_type, artist, title, subtitle, album, 
		       file_hash, file_size, indexed_at, modified_at
		FROM files WHERE file_path = ?
	`, path)

	return scanFileMetadata(row)
}

func (db *DB) GetFileByID(id string) (*FileMetadata, error) {
	row := db.conn.QueryRow(`
		SELECT id, file_path, file_name, file_type, artist, title, subtitle, album, 
		       file_hash, file_size, indexed_at, modified_at
		FROM files WHERE id = ?
	`, id)

	return scanFileMetadata(row)
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanFileMetadata(s scannable) (*FileMetadata, error) {
	var f FileMetadata
	err := s.Scan(&f.ID, &f.FilePath, &f.FileName, &f.FileType,
		&f.Artist, &f.Title, &f.SubTitle, &f.Album, &f.FileHash, &f.FileSize,
		&f.IndexedAt, &f.ModifiedAt)
	if err != nil {
		return nil, err
	}
	return &f, nil
}


func (db *DB) InsertFileBatch(files []*FileMetadata) error {
	if len(files) == 0 {
		return nil
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO files (file_path, file_name, file_type, artist, title, subtitle, album,
		                   file_hash, file_size, modified_at, indexed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(file_path) DO UPDATE SET
		    file_name = excluded.file_name,
		    artist = excluded.artist,
		    title = excluded.title,
		    subtitle = excluded.subtitle,
		    album = excluded.album,
		    file_hash = excluded.file_hash,
		    file_size = excluded.file_size,
		    modified_at = excluded.modified_at,
		    indexed_at = excluded.indexed_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, metadata := range files {
		_, err := stmt.Exec(
			metadata.FilePath, metadata.FileName, metadata.FileType,
			metadata.Artist, metadata.Title, metadata.SubTitle, metadata.Album,
			metadata.FileHash, metadata.FileSize, metadata.ModifiedAt, metadata.IndexedAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *DB) DeleteFileBatch(paths []string) error {
	if len(paths) == 0 {
		return nil
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("DELETE FROM files WHERE file_path = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, path := range paths {
		if _, err := stmt.Exec(path); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *DB) DeleteFile(id string) error {
	_, err := db.conn.Exec("DELETE FROM files WHERE id = ?", id)
	return err
}

func (db *DB) DeleteFileByPath(path string) error {
	_, err := db.conn.Exec("DELETE FROM files WHERE file_path = ?", path)
	return err
}

func (db *DB) FileExists(path string) bool {
	var exists bool
	db.conn.QueryRow("SELECT EXISTS(SELECT 1 FROM files WHERE file_path = ?)", path).Scan(&exists)
	return exists
}

func (db *DB) FileExistsByHash(hash string) (bool, string, error) {
	var filePath string
	err := db.conn.QueryRow("SELECT file_path FROM files WHERE file_hash = ? LIMIT 1", hash).Scan(&filePath)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, filePath, nil
}

type SearchResult struct {
	Results    []*FileMetadata `json:"results"`
	Total      int             `json:"total"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	TotalPages int             `json:"total_pages"`
}

func (db *DB) Search(text string, page, pageSize int, fileType string, artist string, title string) (*SearchResult, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > maxPageSize {
		pageSize = defaultPageSize
	}

	if text != "" {
		result, err := db.searchFTS(text, page, pageSize, fileType, artist, title)
		if err == nil && len(result.Results) > 0 {
			return result, nil
		}
		AppLogger.Info("FTS search returned no results for '%s', trying LIKE fallback", text)
	}

	return db.searchLike(text, page, pageSize, fileType, artist, title)
}

func (db *DB) searchFTS(text string, page, pageSize int, fileType string, artist string, title string) (*SearchResult, error) {
	offset := (page - 1) * pageSize

	var whereConditions []string
	var args []interface{}

	whereConditions = append(whereConditions, "files_fts MATCH ?")
	args = append(args, text)

	if fileType == "gp" {
		whereConditions = append(whereConditions, "f.file_type IN ('gp', 'gpx')")
	} else if fileType != "" {
		whereConditions = append(whereConditions, "f.file_type = ?")
		args = append(args, fileType)
	}

	if artist != "" {
		whereConditions = append(whereConditions, "LOWER(f.artist) LIKE LOWER(?)")
		args = append(args, "%"+artist+"%")
	}

	if title != "" {
		whereConditions = append(whereConditions, "LOWER(f.title) LIKE LOWER(?)")
		args = append(args, "%"+title+"%")
	}

	whereClause := " WHERE " + strings.Join(whereConditions, " AND ")
	joinClause := " JOIN files_fts ON files_fts.rowid = f.id"

	var total int
	countQuery := "SELECT COUNT(*) FROM files f" + joinClause + whereClause
	err := db.conn.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, err
	}

	searchQuery := `
		SELECT f.id, f.file_path, f.file_name, f.file_type,
		       f.artist, f.title, f.subtitle, f.album, f.file_hash, f.file_size,
		       f.indexed_at, f.modified_at
		FROM files f` + joinClause + whereClause + `
		ORDER BY rank
		LIMIT ? OFFSET ?`

	searchArgs := append(args, pageSize, offset)
	rows, err := db.conn.Query(searchQuery, searchArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*FileMetadata
	for rows.Next() {
		f, err := scanFileMetadata(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, f)
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &SearchResult{
		Results:    results,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func (db *DB) searchLike(text string, page, pageSize int, fileType string, artist string, title string) (*SearchResult, error) {
	offset := (page - 1) * pageSize

	var whereConditions []string
	var args []interface{}

	if text != "" {
		whereConditions = append(whereConditions,
			"(LOWER(f.file_name) LIKE LOWER(?) OR LOWER(f.artist) LIKE LOWER(?) OR LOWER(f.title) LIKE LOWER(?) OR LOWER(f.subtitle) LIKE LOWER(?))")
		pattern := "%" + text + "%"
		args = append(args, pattern, pattern, pattern, pattern)
	}

	if fileType == "gp" {
		whereConditions = append(whereConditions, "f.file_type IN ('gp', 'gpx')")
	} else if fileType != "" {
		whereConditions = append(whereConditions, "f.file_type = ?")
		args = append(args, fileType)
	}

	if artist != "" {
		whereConditions = append(whereConditions, "LOWER(f.artist) LIKE LOWER(?)")
		args = append(args, "%"+artist+"%")
	}

	if title != "" {
		whereConditions = append(whereConditions, "LOWER(f.title) LIKE LOWER(?)")
		args = append(args, "%"+title+"%")
	}

	var whereClause string
	if len(whereConditions) > 0 {
		whereClause = " WHERE " + strings.Join(whereConditions, " AND ")
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM files f" + whereClause
	err := db.conn.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, err
	}

	searchQuery := `
		SELECT f.id, f.file_path, f.file_name, f.file_type,
		       f.artist, f.title, f.subtitle, f.album, f.file_hash, f.file_size,
		       f.indexed_at, f.modified_at
		FROM files f` + whereClause + `
		ORDER BY f.indexed_at DESC
		LIMIT ? OFFSET ?`

	searchArgs := append(args, pageSize, offset)
	rows, err := db.conn.Query(searchQuery, searchArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*FileMetadata
	for rows.Next() {
		f, err := scanFileMetadata(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, f)
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &SearchResult{
		Results:    results,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func (db *DB) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	var totalFiles int64
	var totalSize int64
	err := db.conn.QueryRow("SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM files").Scan(&totalFiles, &totalSize)
	if err != nil {
		return nil, err
	}

	stats["total_files"] = totalFiles
	stats["total_size_bytes"] = totalSize
	stats["total_size_gb"] = float64(totalSize) / (1024 * 1024 * 1024)

	rows, err := db.conn.Query("SELECT file_type, COUNT(*) FROM files GROUP BY file_type")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byType := make(map[string]int64)
	for rows.Next() {
		var fileType string
		var count int64
		if err := rows.Scan(&fileType, &count); err != nil {
			continue
		}
		byType[fileType] = count
	}
	stats["by_type"] = byType

	return stats, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}
