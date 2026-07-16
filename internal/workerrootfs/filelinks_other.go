//go:build !windows

package workerrootfs

import (
	"errors"
	"os"
	"reflect"
)

func regularFileLinkCount(_ *os.File, info os.FileInfo) (uint64, error) {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0, errors.New("file metadata is unavailable")
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, errors.New("file metadata is unavailable")
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, errors.New("file metadata is unsupported")
	}
	links := value.FieldByName("Nlink")
	if !links.IsValid() {
		return 0, errors.New("file link count is unsupported")
	}
	switch links.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return links.Uint(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if links.Int() < 0 {
			return 0, errors.New("file link count is invalid")
		}
		return uint64(links.Int()), nil
	default:
		return 0, errors.New("file link count is unsupported")
	}
}
