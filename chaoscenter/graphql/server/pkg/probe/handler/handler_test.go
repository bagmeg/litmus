package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/litmuschaos/litmus/chaoscenter/graphql/server/graph/model"
	"github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/authorization"
	"github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/database/mongodb"
	dbMocks "github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/database/mongodb/mocks"
	dbSchemaProbe "github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/database/mongodb/probe"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type MockServices struct {
	MongodbOperator *dbMocks.MongoOperator
	Probe           Service
}

func NewMockServices() *MockServices {
	var (
		mongodbMockOperator = new(dbMocks.MongoOperator)
	)

	mongodb.Operator = mongodbMockOperator
	return &MockServices{
		MongodbOperator: mongodbMockOperator,
		Probe:           NewProbeService(),
	}
}

func assertExpectations(mockServices *MockServices, t *testing.T) {
	mockServices.MongodbOperator.AssertExpectations(t)
}

func createExpectedProbe(projectID string, request model.ProbeRequest) *model.Probe {
	var (
		currTime = time.Now().UnixMilli()
		username = uuid.New().String()
	)

	newProbe := &dbSchemaProbe.Probe{
		ResourceDetails: mongodb.ResourceDetails{
			Name: request.Name,
			Tags: request.Tags,
		},
		ProjectID: projectID,
		Audit: mongodb.Audit{
			CreatedAt: currTime,
			UpdatedAt: currTime,
			IsRemoved: false,
			CreatedBy: mongodb.UserDetailResponse{
				Username: username,
			},
			UpdatedBy: mongodb.UserDetailResponse{
				Username: username,
			},
		},
		Type:               dbSchemaProbe.ProbeType(request.Type),
		InfrastructureType: request.InfrastructureType,
	}

	if request.Description != nil {
		newProbe.Description = *request.Description
	}

	return newProbe.GetOutputProbe()
}

func TestProbe_AddProbe(t *testing.T) {
	name := uuid.New().String()
	projectID := uuid.New().String()
	username, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{"username": name}).SignedString([]byte(""))
	ctx := context.WithValue(context.Background(), authorization.AuthKey, username)

	tests := []struct {
		name    string
		request model.ProbeRequest
		given   func(mockServices *MockServices)
		wantErr bool
	}{
		{
			name: "Successfully add probe",
			request: model.ProbeRequest{
				Name: "test_probe",
			},
			given: func(mockServices *MockServices) {
				mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

				mockServices.MongodbOperator.On("Create", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Failed to add probe",
			request: model.ProbeRequest{
				Name: "test_probe",
			},
			given: func(mockServices *MockServices) {
				mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

				mockServices.MongodbOperator.On("Create", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(errors.New("failed to add probe")).Once()
			},
			wantErr: true,
		},
		{
			name: "Successfully add HTTP probe",
			request: model.ProbeRequest{
				Name: "test_probe",
				Type: model.ProbeTypeHTTPProbe,
				KubernetesHTTPProperties: &model.KubernetesHTTPProbeRequest{
					Method: &model.MethodRequest{},
				},
			},
			given: func(mockServices *MockServices) {
				mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

				mockServices.MongodbOperator.On("Create", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(nil).Once()
			},
			wantErr: false,
		},
		// TODO: Fix to make this test pass
		// {
		// 	name: "Failed to add probe with wrong type",
		// 	request: model.ProbeRequest{
		// 		Type: "wrong type",
		// 	},
		// 	given: func(mockServices *MockServices) {
		// 		mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

		// 		mockServices.MongodbOperator.On("Create", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(nil).Once()
		// 	},
		// 	wantErr: true,
		// },
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockServices := NewMockServices()
			tc.given(mockServices)

			probe, err := mockServices.Probe.AddProbe(ctx, tc.request, projectID)
			if (err != nil) != tc.wantErr {
				t.Errorf("ProbeService.AddProbe() error = %v", err)
				return
			}

			wantProbe := createExpectedProbe(projectID, tc.request)
			if probe.ProjectID != wantProbe.ProjectID {
				t.Errorf("ProjectID mismatch: got %v, want %v", probe.ProjectID, wantProbe.ProjectID)
			}
			if probe.Name != wantProbe.Name {
				t.Errorf("Name mismatch: got %v, want %v", probe.Name, wantProbe.Name)
			}
			if probe.Type != wantProbe.Type {
				t.Errorf("Type mismatch: got %v, want %v", probe.Type, wantProbe.Type)
			}
			if probe.InfrastructureType != wantProbe.InfrastructureType {
				t.Errorf("InfrastructureType mismatch: got %v, want %v", probe.InfrastructureType, wantProbe.InfrastructureType)
			}

			assertExpectations(mockServices, t)
		})
	}
}

func TestProbe_GetProbe(t *testing.T) {
	projectID := uuid.New().String()
	probeName := uuid.New().String()
	tests := []struct {
		name      string
		given     func(mockServices *MockServices, result *mongo.SingleResult)
		result    *mongo.SingleResult
		wantErr   bool
		expectNil bool
	}{
		{
			name: "Successfully get probe",
			result: mongo.NewSingleResultFromDocument(
				bson.D{
					{Key: "name", Value: probeName},
					{Key: "project_id", Value: projectID}},
				nil, nil),
			given: func(mockServices *MockServices, result *mongo.SingleResult) {
				mockServices.MongodbOperator.On("Get", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(result, nil).Once()
			},
			wantErr:   false,
			expectNil: false,
		},
		{
			name: "Failed to get probe, no document found",
			result: mongo.NewSingleResultFromDocument(
				bson.D{
					{Key: "name", Value: probeName},
					{Key: "project_id", Value: projectID}},
				nil, nil),
			given: func(mockServices *MockServices, result *mongo.SingleResult) {
				mockServices.MongodbOperator.On("Get", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(result, mongo.ErrNoDocuments).Once()
			},
			wantErr:   true,
			expectNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockServices := NewMockServices()
			tc.given(mockServices, tc.result)

			probe, err := mockServices.Probe.GetProbe(context.Background(), probeName, projectID)
			if (err != nil) != tc.wantErr {
				t.Errorf("ProbeService.GetProbe() error = %v", err)
				return
			}

			if (probe == nil) != tc.expectNil {
				t.Errorf("ProbeService.GetProbe() returned %v, expected nil = %v", probe, tc.expectNil)
			}

			assertExpectations(mockServices, t)
		})
	}
}

func TestProbe_UpdateProbe(t *testing.T) {
	name := uuid.New().String()
	projectID := uuid.New().String()
	probeName := uuid.New().String()
	username, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{"username": name}).SignedString([]byte(""))
	ctx := context.WithValue(context.Background(), authorization.AuthKey, username)

	tests := []struct {
		name       string
		given      func(mockServices *MockServices, updateResult *mongo.UpdateResult)
		want       string
		result     *mongo.UpdateResult
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "Successfully update probe",
			given: func(mockServices *MockServices, updateResult *mongo.UpdateResult) {
				mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

				singleResult := mongo.NewSingleResultFromDocument(
					bson.D{
						{Key: "name", Value: probeName},
						{Key: "project_id", Value: projectID}},
					nil, nil)

				mockServices.MongodbOperator.On("Get", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(singleResult, nil).Once()

				mockServices.MongodbOperator.On("Update", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything, mock.Anything).Return(updateResult, nil).Once()
			},
			result: &mongo.UpdateResult{
				MatchedCount:  1,
				ModifiedCount: 1,
				UpsertedCount: 0,
			},
			want:    "Updated successfully",
			wantErr: false,
		},
		{
			name: "No matching probe found",
			given: func(mockServices *MockServices, updateResult *mongo.UpdateResult) {
				mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

				singleResult := mongo.NewSingleResultFromDocument(
					bson.D{
						{Key: "name", Value: probeName},
						{Key: "project_id", Value: projectID}},
					nil, nil)

				mockServices.MongodbOperator.On("Get", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(singleResult, nil).Once()

				mockServices.MongodbOperator.On("Update", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything, mock.Anything).Return(updateResult, nil).Once()
			},
			result: &mongo.UpdateResult{
				MatchedCount:  0,
				ModifiedCount: 0,
				UpsertedCount: 0,
			},
			want:       "",
			wantErr:    true,
			wantErrMsg: "no matching documents found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockServices := NewMockServices()

			tc.given(mockServices, tc.result)

			res, err := mockServices.Probe.UpdateProbe(ctx, model.ProbeRequest{}, projectID)
			if (err != nil) != tc.wantErr {
				t.Errorf("ProbeService.UpdateProbe() error = %v", err)
			}

			if err != nil && err.Error() != tc.wantErrMsg {
				t.Errorf("ProbeService.UpdateProbe() error = %v, want %v", err, tc.wantErrMsg)
			}

			if res != tc.want {
				t.Errorf("ProbeService.UpdateProbe() = %v, want %v", res, tc.want)
			}

			assertExpectations(mockServices, t)
		})
	}
}

func TestProbe_DeleteProbe(t *testing.T) {
	name := uuid.New().String()
	projectID := uuid.New().String()
	probeName := uuid.New().String()
	username, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{"username": name}).SignedString([]byte(""))
	ctx := context.WithValue(context.Background(), authorization.AuthKey, username)

	tests := []struct {
		name         string
		given        func(mockServices *MockServices, deleteResult *mongo.UpdateResult)
		deleteResult *mongo.UpdateResult
		expectResult bool
		wantErr      bool
	}{
		{
			name: "Successfully delete probe",
			given: func(mockServices *MockServices, deleteResult *mongo.UpdateResult) {
				singleResult := mongo.NewSingleResultFromDocument(
					bson.D{
						{Key: "name", Value: probeName},
						{Key: "project_id", Value: projectID}},
					nil, nil)

				mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

				mockServices.MongodbOperator.On("Get", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(singleResult, nil).Once()

				mockServices.MongodbOperator.On("Update", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything, mock.Anything).Return(deleteResult, nil).Once()
			},
			deleteResult: &mongo.UpdateResult{
				MatchedCount:  1,
				ModifiedCount: 1,
				UpsertedCount: 0,
			},
			expectResult: true,
			wantErr:      false,
		},
		{
			name: "No matching probe found",
			given: func(mockServices *MockServices, deleteResult *mongo.UpdateResult) {
				singleResult := mongo.NewSingleResultFromDocument(
					bson.D{
						{Key: "name", Value: probeName},
						{Key: "project_id", Value: projectID}},
					nil, nil)

				mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

				mockServices.MongodbOperator.On("Get", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(singleResult, nil).Once()

				mockServices.MongodbOperator.On("Update", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything, mock.Anything).Return(deleteResult, nil).Once()
			},
			deleteResult: &mongo.UpdateResult{
				MatchedCount:  0,
				ModifiedCount: 0,
				UpsertedCount: 0,
			},
			expectResult: false,
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockServices := NewMockServices()
			tc.given(mockServices, tc.deleteResult)

			res, err := mockServices.Probe.DeleteProbe(ctx, probeName, projectID)
			if (err != nil) != tc.wantErr {
				t.Errorf("ProbeService.DeleteProbe() error = %v", err)
				return
			}

			if res != tc.expectResult {
				t.Errorf("ProbeService.DeleteProbe() = %v, want %v", res, tc.expectResult)
			}
		})
	}
}

func TestProbe_ListProbe(t *testing.T) {
	projectID := uuid.New().String()
	probeName := "test_probe"

	infraStructureType := model.InfrastructureTypeKubernetes
	experimentId := uuid.New().String()
	experimentRunID := uuid.New().String()

	tests := []struct {
		name  string
		given func(mockServices *MockServices)
	}{
		{
			name: "List Probes",
			given: func(mockServices *MockServices) {
				findResult := []interface{}{
					bson.D{
						{Key: "project_id", Value: projectID},
						{Key: "name", Value: probeName},
					},
				}

				findResult2 := []interface{}{bson.D{
					{Key: "experiment_id", Value: experimentId},
					{Key: "experiment_run_id", Value: experimentRunID},
				}}

				cursor, _ := mongo.NewCursorFromDocuments(findResult, nil, nil)
				mockServices.MongodbOperator.On("Aggregate", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything).Return(cursor, nil).Once()

				cursor2, _ := mongo.NewCursorFromDocuments(findResult2, nil, nil)
				mockServices.MongodbOperator.On("Aggregate", mock.Anything, mongodb.ChaosExperimentRunsCollection, mock.Anything, mock.Anything).Return(cursor2, nil).Once()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockServices := NewMockServices()
			tc.given(mockServices)

			_, err := mockServices.Probe.ListProbes(context.Background(), []string{probeName}, &infraStructureType, nil, projectID)

			if err != nil {
				t.Errorf("ProbeService.ListProbes() error = %v", err)
				return
			}
			assertExpectations(mockServices, t)
		})
	}
}

func TestProbe_ValidateUniqueProbe(t *testing.T) {
	tests := []struct {
		name  string
		given func(mockServices *MockServices)
	}{
		{
			name: "Unique",
			given: func(mockServices *MockServices) {
				mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

				mockServices.MongodbOperator.On("CountDocuments", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything).Return(int64(0), nil).Once()
			},
		},
		{
			name: "Not Unique",
			given: func(mockServices *MockServices) {
				mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

				mockServices.MongodbOperator.On("CountDocuments", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything).Return(int64(1), nil).Once()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockServices := NewMockServices()
			tc.given(mockServices)

			_, err := mockServices.Probe.ValidateUniqueProbe(context.Background(), "", "")
			if err != nil {
				t.Errorf("ProbeService.ValidateUniqueProbe() error = %v", err)
				return
			}
		})
	}
}
