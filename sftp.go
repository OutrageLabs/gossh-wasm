// sftp.go implements SFTP file operations over an existing SSH connection.
// Each SFTP session is tied to an SSH session and provides directory listing,
// file manipulation, and metadata operations.

//go:build js && wasm

package gossh

import (
	"fmt"
	"io/fs"
	pathpkg "path"
	"strings"
	"sync"
	"syscall/js"

	"github.com/pkg/sftp"
)

// sftpSession holds an active SFTP client tied to an SSH session.
type sftpSession struct {
	id        string
	sessionID string
	client    *sftp.Client
	strict    bool
}

// sftpStore tracks all active SFTP sessions.
var sftpStore sync.Map

// sftpOpen opens an SFTP subsystem on an existing SSH session.
// Called from JS as: GoSSH.sftpOpen(sessionId) → Promise<sftpId>
func sftpOpen(sessionID string) js.Value {
	return newPromise(func() (any, error) {
		val, ok := sessionStore.Load(sessionID)
		if !ok {
			return nil, fmt.Errorf("sftpOpen: session %q not found", sessionID)
		}
		sess := val.(*session)

		client, err := sftp.NewClient(sess.sshClient)
		if err != nil {
			return nil, fmt.Errorf("sftpOpen: %w", err)
		}

		sftpID := generateID()
		sftpStore.Store(sftpID, &sftpSession{
			id:        sftpID,
			sessionID: sessionID,
			client:    client,
			strict:    sess.strictSFTPPaths,
		})

		return sftpID, nil
	})
}

// sftpClose closes an SFTP session.
// Called from JS as: GoSSH.sftpClose(sftpId)
func sftpClose(sftpID string) {
	val, ok := sftpStore.LoadAndDelete(sftpID)
	if !ok {
		return
	}
	s := val.(*sftpSession)
	closeQuietly(s.client)
}

// sftpListDir lists the contents of a remote directory.
// Called from JS as: GoSSH.sftpListDir(sftpId, path) → Promise<FileInfo[]>
func sftpListDir(sftpID string, remotePath string) js.Value {
	return newPromise(func() (any, error) {
		ss, err := getSFTPSession(sftpID)
		if err != nil {
			return nil, err
		}
		remotePath, err = validateSFTPPath(remotePath, ss.strict)
		if err != nil {
			return nil, fmt.Errorf("sftpListDir: %w", err)
		}

		entries, err := ss.client.ReadDir(remotePath)
		if err != nil {
			return nil, fmt.Errorf("sftpListDir: %w", err)
		}

		result := js.Global().Get("Array").New(len(entries))
		for i, entry := range entries {
			result.SetIndex(i, fileInfoToJS(remotePath, entry))
		}
		return result, nil
	})
}

// sftpStat returns file info for a single path.
// Uses Lstat to correctly identify symlinks (Stat follows them).
// Called from JS as: GoSSH.sftpStat(sftpId, path) → Promise<FileInfo>
func sftpStat(sftpID string, remotePath string) js.Value {
	return newPromise(func() (any, error) {
		ss, err := getSFTPSession(sftpID)
		if err != nil {
			return nil, err
		}
		remotePath, err = validateSFTPPath(remotePath, ss.strict)
		if err != nil {
			return nil, fmt.Errorf("sftpStat: %w", err)
		}

		info, err := ss.client.Lstat(remotePath)
		if err != nil {
			return nil, fmt.Errorf("sftpStat: %w", err)
		}

		return fileInfoToJS(remotePath, info), nil
	})
}

// sftpMkdir creates a remote directory.
// Called from JS as: GoSSH.sftpMkdir(sftpId, path) → Promise<void>
func sftpMkdir(sftpID string, remotePath string) js.Value {
	return newPromise(func() (any, error) {
		ss, err := getSFTPSession(sftpID)
		if err != nil {
			return nil, err
		}
		remotePath, err = validateSFTPPath(remotePath, ss.strict)
		if err != nil {
			return nil, fmt.Errorf("sftpMkdir: %w", err)
		}

		if err := ss.client.MkdirAll(remotePath); err != nil {
			return nil, fmt.Errorf("sftpMkdir: %w", err)
		}
		return nil, nil
	})
}

// sftpRemove removes a file or directory (optionally recursive).
// Called from JS as: GoSSH.sftpRemove(sftpId, path, recursive) → Promise<void>
func sftpRemove(sftpID string, remotePath string, recursive bool) js.Value {
	return newPromise(func() (any, error) {
		ss, err := getSFTPSession(sftpID)
		if err != nil {
			return nil, err
		}
		remotePath, err = validateSFTPPath(remotePath, ss.strict)
		if err != nil {
			return nil, fmt.Errorf("sftpRemove: %w", err)
		}

		if recursive {
			return nil, removeRecursive(ss.client, remotePath)
		}
		if err := ss.client.Remove(remotePath); err != nil {
			return nil, fmt.Errorf("sftpRemove: %w", err)
		}
		return nil, nil
	})
}

// removeRecursive removes a directory and all its contents.
// Uses Lstat to avoid following symlinks (prevents symlink traversal attacks).
func removeRecursive(client *sftp.Client, remotePath string) error {
	info, err := client.Lstat(remotePath)
	if err != nil {
		return err
	}

	// If it's a symlink, just remove the link itself — don't follow it.
	if info.Mode()&fs.ModeSymlink != 0 {
		return client.Remove(remotePath)
	}

	if !info.IsDir() {
		return client.Remove(remotePath)
	}

	entries, err := client.ReadDir(remotePath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		childPath := pathpkg.Join(remotePath, entry.Name())
		if err := removeRecursive(client, childPath); err != nil {
			return err
		}
	}

	return client.RemoveDirectory(remotePath)
}

// sftpRename renames/moves a remote file or directory.
// Called from JS as: GoSSH.sftpRename(sftpId, oldPath, newPath) → Promise<void>
func sftpRename(sftpID string, oldPath, newPath string) js.Value {
	return newPromise(func() (any, error) {
		ss, err := getSFTPSession(sftpID)
		if err != nil {
			return nil, err
		}
		oldPath, err = validateSFTPPath(oldPath, ss.strict)
		if err != nil {
			return nil, fmt.Errorf("sftpRename: oldPath: %w", err)
		}
		newPath, err = validateSFTPPath(newPath, ss.strict)
		if err != nil {
			return nil, fmt.Errorf("sftpRename: newPath: %w", err)
		}

		if err := ss.client.Rename(oldPath, newPath); err != nil {
			return nil, fmt.Errorf("sftpRename: %w", err)
		}
		return nil, nil
	})
}

// sftpChmod changes file permissions.
// Called from JS as: GoSSH.sftpChmod(sftpId, path, mode) → Promise<void>
func sftpChmod(sftpID string, remotePath string, mode uint32) js.Value {
	return newPromise(func() (any, error) {
		ss, err := getSFTPSession(sftpID)
		if err != nil {
			return nil, err
		}
		remotePath, err = validateSFTPPath(remotePath, ss.strict)
		if err != nil {
			return nil, fmt.Errorf("sftpChmod: %w", err)
		}

		if err := ss.client.Chmod(remotePath, fs.FileMode(mode)); err != nil {
			return nil, fmt.Errorf("sftpChmod: %w", err)
		}
		return nil, nil
	})
}

// getSFTPSession retrieves an SFTP session by ID.
func getSFTPSession(sftpID string) (*sftpSession, error) {
	val, ok := sftpStore.Load(sftpID)
	if !ok {
		return nil, fmt.Errorf("sftp session %q not found", sftpID)
	}
	return val.(*sftpSession), nil
}

// getSFTPClient retrieves an SFTP client by ID.
func getSFTPClient(sftpID string) (*sftp.Client, error) {
	ss, err := getSFTPSession(sftpID)
	if err != nil {
		return nil, err
	}
	return ss.client, nil
}

func validateSFTPPath(remotePath string, strict bool) (string, error) {
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return "", fmt.Errorf("path is required")
	}
	if strings.Contains(remotePath, "\x00") || containsCRLF(remotePath) {
		return "", fmt.Errorf("path contains invalid characters")
	}

	if !strict {
		return remotePath, nil
	}

	if strings.Contains(remotePath, "\\") {
		return "", fmt.Errorf("strictSFTPPaths: backslash is not allowed")
	}
	for _, seg := range strings.Split(remotePath, "/") {
		if seg == ".." {
			return "", fmt.Errorf("strictSFTPPaths: parent path traversal is not allowed")
		}
	}

	clean := pathpkg.Clean(remotePath)
	if !strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("strictSFTPPaths: absolute path required")
	}
	return clean, nil
}

// fileInfoToJS converts an fs.FileInfo to a JS object matching the FileInfo interface.
func fileInfoToJS(parentPath string, info fs.FileInfo) js.Value {
	fullPath := pathpkg.Join(parentPath, info.Name())
	if !strings.HasPrefix(fullPath, "/") {
		fullPath = "/" + fullPath
	}

	return js.ValueOf(map[string]any{
		"name":        info.Name(),
		"path":        fullPath,
		"size":        info.Size(),
		"isDir":       info.IsDir(),
		"isSymlink":   info.Mode()&fs.ModeSymlink != 0,
		"permissions": info.Mode().Perm().String(),
		"modTime":     info.ModTime().UnixMilli(),
	})
}
