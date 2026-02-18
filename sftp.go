// sftp.go implements SFTP file operations over an existing SSH connection.
// Each SFTP session is tied to an SSH session and provides directory listing,
// file manipulation, and metadata operations.

//go:build js && wasm

package gossh

import (
	"fmt"
	"io/fs"
	"sync"
	"syscall/js"

	"github.com/pkg/sftp"
)

// sftpSession holds an active SFTP client tied to an SSH session.
type sftpSession struct {
	id        string
	sessionID string
	client    *sftp.Client
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
	s.client.Close()
}

// sftpListDir lists the contents of a remote directory.
// Called from JS as: GoSSH.sftpListDir(sftpId, path) → Promise<FileInfo[]>
func sftpListDir(sftpID string, path string) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		entries, err := client.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("sftpListDir: %w", err)
		}

		result := js.Global().Get("Array").New(len(entries))
		for i, entry := range entries {
			result.SetIndex(i, fileInfoToJS(path, entry))
		}
		return result, nil
	})
}

// sftpStat returns file info for a single path.
// Called from JS as: GoSSH.sftpStat(sftpId, path) → Promise<FileInfo>
func sftpStat(sftpID string, path string) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		info, err := client.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("sftpStat: %w", err)
		}

		return fileInfoToJS(path, info), nil
	})
}

// sftpMkdir creates a remote directory.
// Called from JS as: GoSSH.sftpMkdir(sftpId, path) → Promise<void>
func sftpMkdir(sftpID string, path string) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		if err := client.MkdirAll(path); err != nil {
			return nil, fmt.Errorf("sftpMkdir: %w", err)
		}
		return nil, nil
	})
}

// sftpRemove removes a file or directory (optionally recursive).
// Called from JS as: GoSSH.sftpRemove(sftpId, path, recursive) → Promise<void>
func sftpRemove(sftpID string, path string, recursive bool) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		if recursive {
			return nil, removeRecursive(client, path)
		}
		if err := client.Remove(path); err != nil {
			return nil, fmt.Errorf("sftpRemove: %w", err)
		}
		return nil, nil
	})
}

// removeRecursive removes a directory and all its contents.
func removeRecursive(client *sftp.Client, path string) error {
	info, err := client.Stat(path)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return client.Remove(path)
	}

	entries, err := client.ReadDir(path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		childPath := path + "/" + entry.Name()
		if err := removeRecursive(client, childPath); err != nil {
			return err
		}
	}

	return client.RemoveDirectory(path)
}

// sftpRename renames/moves a remote file or directory.
// Called from JS as: GoSSH.sftpRename(sftpId, oldPath, newPath) → Promise<void>
func sftpRename(sftpID string, oldPath, newPath string) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		if err := client.Rename(oldPath, newPath); err != nil {
			return nil, fmt.Errorf("sftpRename: %w", err)
		}
		return nil, nil
	})
}

// sftpChmod changes file permissions.
// Called from JS as: GoSSH.sftpChmod(sftpId, path, mode) → Promise<void>
func sftpChmod(sftpID string, path string, mode uint32) js.Value {
	return newPromise(func() (any, error) {
		client, err := getSFTPClient(sftpID)
		if err != nil {
			return nil, err
		}

		if err := client.Chmod(path, fs.FileMode(mode)); err != nil {
			return nil, fmt.Errorf("sftpChmod: %w", err)
		}
		return nil, nil
	})
}

// getSFTPClient retrieves an SFTP client by ID.
func getSFTPClient(sftpID string) (*sftp.Client, error) {
	val, ok := sftpStore.Load(sftpID)
	if !ok {
		return nil, fmt.Errorf("sftp session %q not found", sftpID)
	}
	return val.(*sftpSession).client, nil
}

// fileInfoToJS converts an fs.FileInfo to a JS object matching the FileInfo interface.
func fileInfoToJS(parentPath string, info fs.FileInfo) js.Value {
	fullPath := parentPath
	if parentPath != "/" {
		fullPath = parentPath + "/" + info.Name()
	} else {
		fullPath = "/" + info.Name()
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
