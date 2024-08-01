// Code generated by mockery v1.0.0. DO NOT EDIT.

package artifact

import (
	context "context"

	mock "github.com/stretchr/testify/mock"

	types "github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
)

// MockArtifact is an autogenerated mock type for the Artifact type
type MockArtifact struct {
	mock.Mock
}

type ArtifactCleanArgs struct {
	Reference         types.ArtifactReference
	ReferenceAnything bool
}

type ArtifactCleanReturns struct {
	_a0 error
}

type ArtifactCleanExpectation struct {
	Args    ArtifactCleanArgs
	Returns ArtifactCleanReturns
}

func (_m *MockArtifact) ApplyCleanExpectation(e ArtifactCleanExpectation) {
	var args []interface{}
	if e.Args.ReferenceAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Reference)
	}
	_m.On("Clean", args...).Return(e.Returns._a0)
}

func (_m *MockArtifact) ApplyCleanExpectations(expectations []ArtifactCleanExpectation) {
	for _, e := range expectations {
		_m.ApplyCleanExpectation(e)
	}
}

// Clean provides a mock function with given fields: reference
func (_m *MockArtifact) Clean(reference types.ArtifactReference) error {
	return nil
}

type ArtifactInspectArgs struct {
	Ctx         context.Context
	CtxAnything bool
}

type ArtifactInspectReturns struct {
	Reference types.ArtifactReference
	Err       error
}

type ArtifactInspectExpectation struct {
	Args    ArtifactInspectArgs
	Returns ArtifactInspectReturns
}

func (_m *MockArtifact) ApplyInspectExpectation(e ArtifactInspectExpectation) {
	var args []interface{}
	if e.Args.CtxAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Ctx)
	}
	_m.On("Inspect", args...).Return(e.Returns.Reference, e.Returns.Err)
}

func (_m *MockArtifact) ApplyInspectExpectations(expectations []ArtifactInspectExpectation) {
	for _, e := range expectations {
		_m.ApplyInspectExpectation(e)
	}
}

// Inspect provides a mock function with given fields: ctx
func (_m *MockArtifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	ret := _m.Called(ctx)

	var r0 types.ArtifactReference
	if rf, ok := ret.Get(0).(func(context.Context) types.ArtifactReference); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(types.ArtifactReference)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
