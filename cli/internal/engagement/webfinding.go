package engagement

import (
	"errors"
	"os"
	"path/filepath"
)

func (s *Store) AddOnWebFinding(fn func([]byte) error) func() {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	if s.webFindingListeners == nil {
		s.webFindingListeners = map[int]func([]byte) error{}
	}
	id := s.nextID
	s.nextID++
	s.webFindingListeners[id] = fn
	return func() { s.lmu.Lock(); delete(s.webFindingListeners, id); s.lmu.Unlock() }
}

func (s *Store) notifyWebFinding(data []byte) error {
	s.lmu.Lock()
	listeners := make([]func([]byte) error, 0, len(s.webFindingListeners))
	for _, fn := range s.webFindingListeners {
		listeners = append(listeners, fn)
	}
	s.lmu.Unlock()
	var result error
	for _, fn := range listeners {
		if err := fn(data); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s *Store) appendWebFinding(data []byte) error {
	if err := s.webBlobDir(); err != nil {
		return err
	}
	path := filepath.Join(s.EvidenceDir(), "web", "findings.jsonl")
	st, err := os.Lstat(path)
	flags := os.O_APPEND | os.O_WRONLY
	if os.IsNotExist(err) {
		flags |= os.O_CREATE | os.O_EXCL
	} else if err != nil {
		return err
	} else if !st.Mode().IsRegular() {
		return errors.New("invalid finding log file")
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || st != nil && !os.SameFile(st, opened) {
		return errors.New("finding log changed during open")
	}
	if opened.Size()+int64(len(data)+1) > 32<<20 {
		return errors.New("finding log limit exhausted")
	}
	if err = f.Chmod(0600); err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	return err
}
