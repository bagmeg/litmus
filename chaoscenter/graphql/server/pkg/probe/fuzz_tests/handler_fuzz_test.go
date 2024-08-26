package fuzz_tests

import (
	"context"
	"testing"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/authorization"
	dbMocks "github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/database/mongodb/mocks"
	"github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/database/mongodb/probe"
	dbSchemaProbe "github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/database/mongodb/probe"

	"github.com/litmuschaos/litmus/chaoscenter/graphql/server/graph/model"
	"github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/database/mongodb"
	"github.com/litmuschaos/litmus/chaoscenter/graphql/server/pkg/probe/handler"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type MockServices struct {
	MongodbOperator *dbMocks.MongoOperator
	Probe           handler.Service
}

func NewMockServices() *MockServices {
	var (
		mongodbMockOperator = new(dbMocks.MongoOperator)
	)

	mongodb.Operator = mongodbMockOperator
	return &MockServices{
		MongodbOperator: mongodbMockOperator,
		Probe:           handler.NewProbeService(),
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

func FuzzAddProbe(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzConsumer := fuzz.NewConsumer(data)
		fuzzConsumer.AllowUnexportedFields()

		var request model.ProbeRequest
		if err := fuzzConsumer.GenerateStruct(&request); err != nil {
			return
		}

		projectID := uuid.New().String()
		username, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{"username": uuid.New().String()}).SignedString([]byte(""))
		ctx := context.WithValue(context.Background(), authorization.AuthKey, username)

		mockServices := NewMockServices()
		mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()
		mockServices.MongodbOperator.On("Create", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(nil).Once()

		probe, err := mockServices.Probe.AddProbe(ctx, model.ProbeRequest{}, projectID)
		// Assert probe response and error handling
		if err != nil && err.Error() != "failed to add probe" {
			t.Errorf("Probe.AddProbe() unexpected error = %v", err)
			return
		}

		if probe != nil {
			wantProbe := createExpectedProbe(projectID, request)
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
		}

		assertExpectations(mockServices, t)
	})
}

func FuzzGetProbe(f *testing.F) {

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzConsumer := fuzz.NewConsumer(data)
		fuzzConsumer.AllowUnexportedFields()
		targetStruct := &struct {
			probeName string
			projectID string
		}{}

		if err := fuzzConsumer.GenerateStruct(targetStruct); err != nil {
			return
		}

		ctx := context.Background()
		mockServices := NewMockServices()

		singleResult := mongo.NewSingleResultFromDocument(bson.D{
			{"project_id", targetStruct.projectID},
			{"name", targetStruct.probeName},
			{"description", "Test Description"},
			{"tags", []string{"tag1", "tag2"}},
			{"updated_at", time.Now().Unix()},
			{"created_at", time.Now().Unix()},
			{"created_by", bson.D{
				{"user_id", "test_user_id"},
				{"username", "test_user"},
				{"email", "test@litmus.com"},
			}},
			{"updated_by", bson.D{
				{"user_id", "test_user_update_id"},
				{"username", "test_user_update"},
				{"email", "test_update@litmus.com"},
			}},
			{"type", model.ProbeTypeHTTPProbe},
			{"infrastructure_type", model.InfrastructureTypeKubernetes},
			{"kubernetes_http_properties", &probe.KubernetesHTTPProbe{
				URL:          "http://localhost:8080",
				ProbeTimeout: "5s",
				Interval:     "10s",
				Method:       probe.Method{},
			}},
			{"recent_executions", []*model.ProbeRecentExecutions{}},
			{"average_success_percentage", 100},
		}, nil, nil)

		mockServices.MongodbOperator.On("Get", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(singleResult, nil).Once()

		probe, err := mockServices.Probe.GetProbe(ctx, targetStruct.probeName, targetStruct.projectID)
		if err != nil {
			t.Errorf("Porbe.GetProbe() error = %v", err)
		}

		if probe == nil {
			t.Errorf("Returned response is nil")
		}

		if probe.Name != targetStruct.probeName {
			t.Errorf("Expected probe name %v, but got %v", targetStruct.probeName, probe.Name)
		}
		if probe.ProjectID != targetStruct.projectID {
			t.Errorf("Expected project ID %v, but got %v", targetStruct.projectID, probe.ProjectID)
		}
	})
}

func FuzzDeleteProbe(f *testing.F) {
	name := uuid.New().String()
	username, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{"username": name}).SignedString([]byte(""))
	ctx := context.WithValue(context.Background(), authorization.AuthKey, username)

	deleteResults := []*mongo.UpdateResult{
		{1, 1, 0, nil},
		{0, 0, 0, nil},
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzConsumer := fuzz.NewConsumer(data)
		fuzzConsumer.AllowUnexportedFields()
		targetStruct := &struct {
			probeName string
			projectID string
		}{}

		if err := fuzzConsumer.GenerateStruct(targetStruct); err != nil {
			return
		}

		mockServices := NewMockServices()

		singleResult := mongo.NewSingleResultFromDocument(
			bson.D{
				{Key: "name", Value: targetStruct.probeName},
				{Key: "project_id", Value: targetStruct.probeName}},
			nil, nil)

		idx, _ := fuzzConsumer.GetInt()
		deleteResult := deleteResults[idx%2]

		mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()
		mockServices.MongodbOperator.On("Get", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(singleResult, nil).Once()
		mockServices.MongodbOperator.On("Update", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything, mock.Anything).Return(deleteResult, nil).Once()

		res, err := mockServices.Probe.DeleteProbe(ctx, targetStruct.probeName, targetStruct.projectID)

		if err != nil {
			t.Errorf("Probe.DeleteProbe() error = %v", err)
		}

		if !res {
			t.Errorf("Returned response is false")
		}
	})
}

func FuzzUpdateProbe(f *testing.F) {
	name := uuid.New().String()
	username, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{"username": name}).SignedString([]byte(""))
	ctx := context.WithValue(context.Background(), authorization.AuthKey, username)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzConsumer := fuzz.NewConsumer(data)
		fuzzConsumer.AllowUnexportedFields()
		targetStruct := &struct {
			probeName string
			projectID string
		}{}

		if err := fuzzConsumer.GenerateStruct(targetStruct); err != nil {
			return
		}

		mockServices := NewMockServices()

		singleResult := mongo.NewSingleResultFromDocument(
			bson.D{
				{Key: "name", Value: targetStruct.probeName},
				{Key: "project_id", Value: targetStruct.projectID}},
			nil, nil)

		updateResult := &mongo.UpdateResult{
			MatchedCount:  1,
			ModifiedCount: 1,
			UpsertedCount: 0,
		}
		mockServices.MongodbOperator.On("GetAuthConfig", mock.Anything, mock.Anything).Return(&mongodb.AuthConfig{}, nil).Once()

		mockServices.MongodbOperator.On("Get", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything).Return(singleResult, nil).Once()

		mockServices.MongodbOperator.On("Update", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything, mock.Anything).Return(updateResult, nil).Once()

		res, err := mockServices.Probe.UpdateProbe(ctx, model.ProbeRequest{}, targetStruct.projectID)
		if err != nil {
			t.Errorf("Probe.UpdateProbe() error = %v", err)
		}

		if res != "Updated successfully" {
			t.Errorf("Returned response is not equal to \"Updated successfully\"")
		}
	})
}

// TODO: 여기서 필터랑 적용되는지 확인 필요
func FuzzListProbe(f *testing.F) {
	infraStructureType := model.InfrastructureTypeKubernetes
	probeName := "test_probe"
	filterDateRange := &model.DateRange{}
	filterType := model.ProbeTypeHTTPProbe

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzConsumer := fuzz.NewConsumer(data)
		fuzzConsumer.AllowUnexportedFields()

		targetStruct := &struct {
			probeName       string
			projectID       string
			experimentID    string
			experimentRunID string
		}{}
		if err := fuzzConsumer.GenerateStruct(targetStruct); err != nil {
			return
		}

		mockServices := NewMockServices()

		findResult := []interface{}{
			bson.D{
				{Key: "name", Value: targetStruct.probeName},
				{Key: "project_id", Value: targetStruct.projectID},
			},
		}

		findResult2 := []interface{}{bson.D{
			{Key: "experiment_id", Value: targetStruct.experimentID},
			{Key: "experiment_run_id", Value: targetStruct.experimentRunID},
		}}

		cursor, _ := mongo.NewCursorFromDocuments(findResult, nil, nil)
		mockServices.MongodbOperator.On("Aggregate", mock.Anything, mongodb.ChaosProbeCollection, mock.Anything, mock.Anything).Return(cursor, nil).Once()

		cursor2, _ := mongo.NewCursorFromDocuments(findResult2, nil, nil)
		mockServices.MongodbOperator.On("Aggregate", mock.Anything, mongodb.ChaosExperimentRunsCollection, mock.Anything, mock.Anything).Return(cursor2, nil).Once()

		filter := &model.ProbeFilterInput{
			Name:      &probeName,
			DateRange: filterDateRange,
			Type:      []*model.ProbeType{&filterType},
		}

		_, err := mockServices.Probe.ListProbes(context.Background(), []string{probeName}, &infraStructureType, filter, targetStruct.projectID)

		if err != nil {
			t.Errorf("Probe.ListProbes() error = %v", err)
		}
	})
}
