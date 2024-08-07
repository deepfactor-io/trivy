// Code generated by mockery v1.0.0. DO NOT EDIT.

package local

import (
	mock "github.com/stretchr/testify/mock"

	types "github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
)

// MockApplier is an autogenerated mock type for the Applier type
type MockApplier struct {
	mock.Mock
}

type ApplierApplyLayersArgs struct {
	ArtifactID         string
	ArtifactIDAnything bool
	BlobIDs            []string
	BlobIDsAnything    bool
}

type ApplierApplyLayersReturns struct {
	Detail types.ArtifactDetail
	Err    error
}

type ApplierApplyLayersExpectation struct {
	Args    ApplierApplyLayersArgs
	Returns ApplierApplyLayersReturns
}

func (_m *MockApplier) ApplyApplyLayersExpectation(e ApplierApplyLayersExpectation) {
	var args []interface{}
	if e.Args.ArtifactIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.ArtifactID)
	}
	if e.Args.BlobIDsAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.BlobIDs)
	}
	_m.On("ApplyLayers", args...).Return(e.Returns.Detail, e.Returns.Err)
}

func (_m *MockApplier) ApplyApplyLayersExpectations(expectations []ApplierApplyLayersExpectation) {
	for _, e := range expectations {
		_m.ApplyApplyLayersExpectation(e)
	}
}

// ApplyLayers provides a mock function with given fields: artifactID, blobIDs
func (_m *MockApplier) ApplyLayers(artifactID string, blobIDs []string) (types.ArtifactDetail, error) {
	ret := _m.Called(artifactID, blobIDs)

	var r0 types.ArtifactDetail
	if rf, ok := ret.Get(0).(func(string, []string) types.ArtifactDetail); ok {
		r0 = rf(artifactID, blobIDs)
	} else {
		r0 = ret.Get(0).(types.ArtifactDetail)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, []string) error); ok {
		r1 = rf(artifactID, blobIDs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
