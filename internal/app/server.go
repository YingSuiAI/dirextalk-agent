package app

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairingworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

type Server struct {
	grpc   *grpc.Server
	health *health.Server
}

type serverOptions struct {
	runtimeCoordinator      rpcapi.RuntimeCoordinator
	runtimeFeatures         rpcapi.RuntimeFeatures
	secretBootstrap         rpcapi.SecretBootstrapManager
	cloudCoordinator        cloudapp.Coordinator
	cloudDestroy            rpcapi.CloudDestroyCoordinator
	cloudEntrypoint         rpcapi.CloudEntrypointCoordinator
	cloudFoundation         rpcapi.CloudFoundationCoordinator
	cloudManaged            rpcapi.CloudManagedAcceptanceCoordinator
	cloudPreparation        rpcapi.CloudManagedPreparationCoordinator
	cloudPairing            rpcapi.CloudPairingCoordinator
	cloudPairingApprovals   rpcapi.CloudPairingApprovalCoordinator
	cloudGoals              rpcapi.CloudGoalPlanner
	cloudHealth             cloudstatus.HealthReader
	workerService           *worker.Service
	workerVerifier          rpcapi.WorkerIdentityVerifier
	workerMaterializer      rpcapi.WorkerIdentityMaterializer
	rootHelperApprovals     rpcapi.RootHelperKeyApprovalCoordinator
	rootHelperDeliveries    *helperkey.Service
	workerOperations        *workeroperation.Service
	rootHelperCapabilities  rpcapi.RootHelperCapabilityIssuer
	pairingWorkerOperations *pairingworker.Service
	pairingCapabilities     rpcapi.PairingWorkerCapabilityIssuer
	pairingReceiptVerifier  rpcapi.PairingWorkerReceiptVerifier
	agentInstanceID         string
}

func WithPairingWorkerControl(operations *pairingworker.Service, capabilities rpcapi.PairingWorkerCapabilityIssuer,
	verifier rpcapi.PairingWorkerReceiptVerifier,
) ServerOption {
	return func(options *serverOptions) {
		options.pairingWorkerOperations, options.pairingCapabilities, options.pairingReceiptVerifier =
			operations, capabilities, verifier
	}
}

type ServerOption func(*serverOptions)

func WithRuntime(coordinator rpcapi.RuntimeCoordinator, features rpcapi.RuntimeFeatures) ServerOption {
	return func(options *serverOptions) {
		options.runtimeCoordinator = coordinator
		options.runtimeFeatures = features
	}
}

func WithSecretBootstrap(manager rpcapi.SecretBootstrapManager, agentInstanceID string) ServerOption {
	return func(options *serverOptions) {
		options.secretBootstrap = manager
		options.agentInstanceID = agentInstanceID
	}
}

func WithCloudControl(coordinator cloudapp.Coordinator) ServerOption {
	return func(options *serverOptions) { options.cloudCoordinator = coordinator }
}

func WithCloudDestroy(coordinator rpcapi.CloudDestroyCoordinator) ServerOption {
	return func(options *serverOptions) { options.cloudDestroy = coordinator }
}

func WithCloudEntrypoint(coordinator rpcapi.CloudEntrypointCoordinator) ServerOption {
	return func(options *serverOptions) { options.cloudEntrypoint = coordinator }
}

func WithCloudPairing(coordinator rpcapi.CloudPairingCoordinator, approvals rpcapi.CloudPairingApprovalCoordinator) ServerOption {
	return func(options *serverOptions) {
		options.cloudPairing, options.cloudPairingApprovals = coordinator, approvals
	}
}
func WithCloudFoundation(coordinator rpcapi.CloudFoundationCoordinator) ServerOption {
	return func(options *serverOptions) { options.cloudFoundation = coordinator }
}

func WithCloudManagedAcceptance(coordinator rpcapi.CloudManagedAcceptanceCoordinator) ServerOption {
	return func(options *serverOptions) { options.cloudManaged = coordinator }
}

func WithCloudManagedPreparation(coordinator rpcapi.CloudManagedPreparationCoordinator) ServerOption {
	return func(options *serverOptions) { options.cloudPreparation = coordinator }
}

func WithCloudGoals(planner rpcapi.CloudGoalPlanner) ServerOption {
	return func(options *serverOptions) { options.cloudGoals = planner }
}

func WithCloudHealth(reader cloudstatus.HealthReader) ServerOption {
	return func(options *serverOptions) { options.cloudHealth = reader }
}

func WithWorkerControl(service *worker.Service) ServerOption {
	return func(options *serverOptions) { options.workerService = service }
}

func WithWorkerIdentity(verifier rpcapi.WorkerIdentityVerifier, materializer rpcapi.WorkerIdentityMaterializer) ServerOption {
	return func(options *serverOptions) {
		options.workerVerifier = verifier
		options.workerMaterializer = materializer
	}
}

func WithRootHelperControl(approvals rpcapi.RootHelperKeyApprovalCoordinator, deliveries *helperkey.Service,
	operations *workeroperation.Service, capabilities rpcapi.RootHelperCapabilityIssuer) ServerOption {
	return func(options *serverOptions) {
		options.rootHelperApprovals, options.rootHelperDeliveries, options.workerOperations = approvals, deliveries, operations
		options.rootHelperCapabilities = capabilities
	}
}

func NewServer(store *postgres.Store, pepper []byte, certFile, keyFile string, optionValues ...ServerOption) (*Server, error) {
	if store == nil {
		return nil, errors.New("postgres store is required")
	}
	if err := config.ValidateMountedSecretFile(keyFile); err != nil {
		return nil, errors.New("TLS private key must be a protected mounted secret file")
	}
	options := serverOptions{}
	for _, option := range optionValues {
		if option != nil {
			option(&options)
		}
	}
	helperParts := 0
	if options.rootHelperApprovals != nil {
		helperParts++
	}
	if options.rootHelperDeliveries != nil {
		helperParts++
	}
	if options.workerOperations != nil {
		helperParts++
	}
	if options.rootHelperCapabilities != nil {
		helperParts++
	}
	if helperParts != 0 && helperParts != 4 {
		return nil, errors.New("root helper control requires complete approval, delivery, Worker operation, and capability-issuer composition")
	}
	rootHelperEnabled := helperParts == 4
	if rootHelperEnabled && options.workerService == nil {
		return nil, errors.New("root helper control requires Worker session authentication")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	authenticator, err := auth.NewAuthenticator(store, pepper)
	if err != nil {
		return nil, err
	}
	var cloudStatuses *postgres.CloudStatusStore
	if options.cloudHealth != nil {
		cloudStatuses, err = postgres.NewCloudStatusStore(store, options.cloudHealth)
	} else {
		cloudStatuses, err = postgres.NewCloudStatusStore(store)
	}
	if err != nil {
		return nil, errors.New("cloud status persistence could not be initialized")
	}
	scopes := map[string]string{
		agentv1.TaskService_CreateTask_FullMethodName:                                    "task.write",
		agentv1.TaskService_GetTask_FullMethodName:                                       "task.read",
		agentv1.TaskService_ListTasks_FullMethodName:                                     "task.read",
		agentv1.TaskService_CancelTask_FullMethodName:                                    "task.write",
		agentv1.TaskService_ListSteps_FullMethodName:                                     "task.read",
		agentv1.TaskService_WatchEvents_FullMethodName:                                   "event.read",
		agentv1.RuntimeService_GetCapabilities_FullMethodName:                            "runtime.read",
		agentv1.RuntimeService_GetRuntimeConfig_FullMethodName:                           "runtime.read",
		agentv1.RuntimeService_PutRuntimeConfig_FullMethodName:                           "runtime.write",
		agentv1.RuntimeService_Chat_FullMethodName:                                       "runtime.chat",
		agentv1.RuntimeService_StreamChat_FullMethodName:                                 "runtime.chat",
		agentv1.CloudControlService_GetCapabilities_FullMethodName:                       "cloud.read",
		agentv1.CloudControlService_CreateCloudGoal_FullMethodName:                       "cloud.plan.write",
		agentv1.CloudControlService_PreviewAwsIdentity_FullMethodName:                    "cloud.connection.preview",
		agentv1.CloudControlService_CreateCloudQuote_FullMethodName:                      "cloud.plan.write",
		agentv1.CloudControlService_GetCloudQuote_FullMethodName:                         "cloud.read",
		agentv1.CloudControlService_CreateCloudPlan_FullMethodName:                       "cloud.plan.write",
		agentv1.CloudControlService_GetCloudPlan_FullMethodName:                          "cloud.read",
		agentv1.CloudControlService_ListCloudPlans_FullMethodName:                        "cloud.read",
		agentv1.CloudControlService_CreateApprovalChallenge_FullMethodName:               "cloud.approve",
		agentv1.CloudControlService_ApproveCloudPlan_FullMethodName:                      "cloud.approve",
		agentv1.CloudControlService_EstablishAwsConnection_FullMethodName:                "cloud.connection.write",
		agentv1.CloudControlService_CreateAwsFoundationOperationChallenge_FullMethodName: "cloud.approve",
		agentv1.CloudControlService_ApproveAwsFoundationOperation_FullMethodName:         "cloud.approve",
		agentv1.CloudControlService_GetAwsFoundationOperation_FullMethodName:             "cloud.read",
		agentv1.CloudControlService_GetCloudConnection_FullMethodName:                    "cloud.read",
		agentv1.CloudControlService_ListCloudConnections_FullMethodName:                  "cloud.read",
		agentv1.CloudControlService_GetCloudDeployment_FullMethodName:                    "cloud.read",
		agentv1.CloudControlService_ListCloudDeployments_FullMethodName:                  "cloud.read",
		agentv1.CloudControlService_GetCloudResource_FullMethodName:                      "cloud.read",
		agentv1.CloudControlService_ListCloudResources_FullMethodName:                    "cloud.read",
		agentv1.CloudControlService_GetCloudWorker_FullMethodName:                        "cloud.read",
		agentv1.CloudControlService_ListCloudWorkers_FullMethodName:                      "cloud.read",
		agentv1.CloudControlService_CreateCloudDeploymentDestroyChallenge_FullMethodName: "cloud.destroy",
		agentv1.CloudControlService_ApproveCloudDeploymentDestroy_FullMethodName:         "cloud.destroy",
		agentv1.CloudControlService_GetCloudDestroyOperation_FullMethodName:              "cloud.read",
		agentv1.CloudControlService_CreateCloudDeploymentEntryPlan_FullMethodName:        "cloud.plan.write",
		agentv1.CloudControlService_GetCloudEntryPlan_FullMethodName:                     "cloud.read",
		agentv1.CloudControlService_CreateCloudDeploymentEntryChallenge_FullMethodName:   "cloud.approve",
		agentv1.CloudControlService_ApproveCloudDeploymentEntry_FullMethodName:           "cloud.approve",
		agentv1.CloudControlService_GetCloudEntryOperation_FullMethodName:                "cloud.read",
		agentv1.CloudControlService_CreateCloudManagedAcceptanceChallenge_FullMethodName: "cloud.approve",
		agentv1.CloudControlService_ApproveCloudManagedAcceptance_FullMethodName:         "cloud.approve",
		agentv1.CloudControlService_GetCloudManagedAcceptanceOperation_FullMethodName:    "cloud.read",
		agentv1.CloudControlService_CreateCloudManagedPreparation_FullMethodName:         "cloud.approve",
		agentv1.CloudControlService_ApproveCloudManagedPreparation_FullMethodName:        "cloud.approve",
		agentv1.CloudControlService_GetCloudManagedPreparation_FullMethodName:            "cloud.read",
		agentv1.CloudControlService_GetCloudPairing_FullMethodName:                       "cloud.read",
		agentv1.CloudControlService_RetrieveCloudPairingPayload_FullMethodName:           "cloud.read",
		agentv1.CloudControlService_CreateCloudPairingResumeChallenge_FullMethodName:     "cloud.approve",
		agentv1.CloudControlService_ApproveCloudPairingResume_FullMethodName:             "cloud.approve",
		agentv1.CloudControlService_PrepareRootHelperKeyDeliveryApproval_FullMethodName:  "cloud.approve",
		agentv1.CloudControlService_ApproveRootHelperKeyDelivery_FullMethodName:          "cloud.approve",
		agentv1.CloudControlService_GetRootHelperKeyDeliveryApproval_FullMethodName:      "cloud.read",
		agentv1.SecretBootstrapService_CreateSession_FullMethodName:                      "secret.bootstrap",
		agentv1.SecretBootstrapService_GetSession_FullMethodName:                         "secret.bootstrap",
		agentv1.SecretBootstrapService_UploadEncrypted_FullMethodName:                    "secret.bootstrap",
		agentv1.SecretBootstrapService_Complete_FullMethodName:                           "secret.bootstrap",
		agentv1.AdminService_CreateServiceKey_FullMethodName:                             "admin.credentials",
		agentv1.AdminService_RevokeServiceKey_FullMethodName:                             "admin.credentials",
	}
	serviceKeyScopes := auth.StaticScopeResolver(scopes)
	resolver := auth.ScopeResolver(func(fullMethod string) (string, bool) {
		if isWorkerSelfAuthenticatedMethod(fullMethod) {
			return "", false
		}
		return serviceKeyScopes(fullMethod)
	})
	unary, stream := auth.NewInterceptors(authenticator, resolver)
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})),
		grpc.ChainUnaryInterceptor(unary), grpc.ChainStreamInterceptor(stream),
		grpc.MaxRecvMsgSize(4<<20), grpc.MaxSendMsgSize(4<<20),
	)
	agentv1.RegisterTaskServiceServer(grpcServer, rpcapi.NewTaskService(store))
	agentv1.RegisterAdminServiceServer(grpcServer, rpcapi.NewAdminService(store, pepper))
	agentv1.RegisterRuntimeServiceServer(grpcServer, rpcapi.NewRuntimeServiceWithCloudDialogue(options.runtimeCoordinator, options.runtimeFeatures, cloudStatuses))
	cloudControl := rpcapi.NewCloudControlServiceWithGoals(options.cloudCoordinator, options.agentInstanceID, cloudStatuses, options.cloudDestroy, options.cloudGoals, options.cloudEntrypoint).
		WithFoundation(options.cloudFoundation).
		WithManagedAcceptance(options.cloudManaged).
		WithManagedPreparation(options.cloudPreparation).
		WithPairing(options.cloudPairing, options.cloudPairingApprovals)
	if rootHelperEnabled {
		cloudControl.WithRootHelperKeyApprovals(options.rootHelperApprovals)
	}
	agentv1.RegisterCloudControlServiceServer(grpcServer, cloudControl)
	agentv1.RegisterSecretBootstrapServiceServer(grpcServer, rpcapi.NewSecretBootstrapService(options.secretBootstrap, options.agentInstanceID))
	agentv1.RegisterWorkerControlServiceServer(grpcServer, rpcapi.NewWorkerControlService(options.workerService, options.workerVerifier, options.workerMaterializer))
	if rootHelperEnabled {
		agentv1.RegisterWorkerServiceOperationServiceServer(grpcServer, rpcapi.NewWorkerServiceOperationService(
			options.workerService, options.workerOperations, options.rootHelperCapabilities))
		agentv1.RegisterRootHelperBootstrapControlServiceServer(grpcServer, rpcapi.NewRootHelperBootstrapControlService(
			options.workerService, options.rootHelperDeliveries, options.rootHelperCapabilities))
		if options.pairingWorkerOperations != nil && options.pairingCapabilities != nil && options.pairingReceiptVerifier != nil {
			agentv1.RegisterPairingWorkerOperationServiceServer(grpcServer, rpcapi.NewPairingWorkerOperationService(
				options.workerService, options.pairingWorkerOperations, options.pairingCapabilities, options.pairingReceiptVerifier))
		}
	}
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, healthServer)
	return &Server{grpc: grpcServer, health: healthServer}, nil
}

func isWorkerSelfAuthenticatedMethod(fullMethod string) bool {
	switch fullMethod {
	case agentv1.WorkerControlService_CreateIdentityChallenge_FullMethodName,
		agentv1.WorkerControlService_EnrollVerifiedIdentity_FullMethodName,
		agentv1.WorkerControlService_Enroll_FullMethodName,
		agentv1.WorkerControlService_GetCurrentAssignment_FullMethodName,
		agentv1.WorkerControlService_Claim_FullMethodName,
		agentv1.WorkerControlService_Heartbeat_FullMethodName,
		agentv1.WorkerControlService_RecordEvidence_FullMethodName,
		agentv1.WorkerControlService_Complete_FullMethodName,
		agentv1.WorkerServiceOperationService_Get_FullMethodName,
		agentv1.WorkerServiceOperationService_Claim_FullMethodName,
		agentv1.WorkerServiceOperationService_AcquireNext_FullMethodName,
		agentv1.WorkerServiceOperationService_Complete_FullMethodName,
		agentv1.PairingWorkerOperationService_AcquireNext_FullMethodName,
		agentv1.PairingWorkerOperationService_Complete_FullMethodName,
		agentv1.RootHelperBootstrapControlService_AcquirePending_FullMethodName,
		agentv1.RootHelperBootstrapControlService_Current_FullMethodName,
		agentv1.RootHelperBootstrapControlService_SubmitProof_FullMethodName,
		agentv1.RootHelperBootstrapControlService_ReconcileRevocation_FullMethodName,
		agentv1.RootHelperBootstrapControlService_ConfirmCanary_FullMethodName:
		return true
	default:
		return false
	}
}

func (server *Server) Serve(listener net.Listener) error { return server.grpc.Serve(listener) }

func (server *Server) Shutdown(ctx context.Context) error {
	server.health.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)
	stopped := make(chan struct{})
	go func() {
		server.grpc.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
		return nil
	case <-ctx.Done():
		server.grpc.Stop()
		<-stopped
		return ctx.Err()
	}
}

func (server *Server) Stop() { server.grpc.Stop() }
