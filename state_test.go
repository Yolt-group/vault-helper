package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/mock"
)

type stateReaderMock struct {
	mock.Mock
}

func (m stateReaderMock) read() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func Test_CheckHelperVersion(t *testing.T) {
	// make sure that this version is higher than the currently required state version
	version = "20.0.0"

	var tests = []struct {
		expectedError bool
		state         State
	}{{
		expectedError: false,
		state: State{HelperVersion: version,
			Username: "testUser",
			Role:     "testRole"},
	},
		{
			expectedError: true,
			state: State{HelperVersion: "0.0.1",
				Username: "testUser",
				Role:     "testRole"},
		},
	}

	for nr, test := range tests {

		printTestCycle(t, nr+1, len(tests))

		bytes, _ := json.Marshal(test.state)

		var m stateReaderMock
		m.On("read").Return(string(bytes), nil)

		_, err := loadState(m)
		errorTestValidate(t, test.expectedError, err)
	}
}
