package common

import (
	"fmt"
)

type Error struct {
	info string
}

func (e *Error) Error() string {
	return e.info
}

func (e *Error) Base(err error) *Error {
	if err != nil {
		e.info += " | " + err.Error()
	}
	return e
}

func NewError(info string) *Error {
	return &Error{
		info: info,
	}
}

func Must(err error) {
	if err != nil {
		fmt.Println(err)
		// 当调用 panic 时，当前的执行流程会立即中止，程序开始执行延迟的清理（如 defer 语句），并最终导致程序崩溃
		panic(err)
	}
}

func Must2(_ interface{}, err error) {
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
}
