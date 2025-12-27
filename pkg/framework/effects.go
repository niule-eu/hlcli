package framework

import (
	"bufio"
	"errors"
	"log"
	"os"
)

type Effect interface {
	Apply() error
}

type FileWriteIO struct {
	Path        string
	Content     []byte
	Mode        int
	Permissions os.FileMode
}

func NewDefaultFileWriteIO(path string, content []byte) *FileWriteIO {
	return &FileWriteIO{
		Path:        path,
		Content:     content,
		Mode:        os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
		Permissions: 0644,
	}
}

func (fw FileWriteIO) Apply() error {
	f, err := os.OpenFile(fw.Path, fw.Mode, fw.Permissions)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := bufio.NewWriter(f)
	_, err = buf.Write(fw.Content)
	if err != nil {
		return err
	}

	f.Sync()
	buf.Flush()
	return nil
}

type FileDeleteIO struct {
	Path string
	Op   func(string) error
}

func (fdio *FileDeleteIO) Apply() error {
	return fdio.Op(fdio.Path)
}

type NoOp struct{}

func (n *NoOp) Apply() error {
	return nil
}

type StdOutIO struct {
	Message string
}

func (sdtoutio *StdOutIO) Apply() error {
	log.Println(sdtoutio.Message)
	return nil
}

func NewStdOutIO(msg string) *StdOutIO {
	return &StdOutIO{
		Message: msg,
	}
}

type CompoundEffect struct {
	Effects []Effect
}

func (fw CompoundEffect) Apply() error {
	var errs []error
	for _, e := range fw.Effects {
		if err := e.Apply(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

func Invoke(effect ...Effect) error {
	var errs []error
	for _, e := range effect {
		if err := e.Apply(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}
