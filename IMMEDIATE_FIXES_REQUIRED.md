# 🔧 立即需要修复的关键问题

**优先级**: P0 (阻断)
**预计时间**: 2-4 小时

---

## 1. ✅ 集成 Registry 到 Server

**文件**: `internal/capability/server/server.go`
**问题**: Server 无法访问 Registry

**修复**:
```go
// 在 Server 结构体中添加
registry *agentcapability.Registry

// 在 New() 中设置
func New(config *Config, registry *agentcapability.Registry) (*Server, error) {
    s := &Server{
        config:   config,
        registry: registry,  // 添加这行
        ...
    }
}
```

## 2. ✅ 实现 DescribeCapabilities

**文件**: `internal/capability/server/handlers.go`
**问题**: 返回空列表

**修复**:
```go
func (s *Server) DescribeCapabilities(ctx context.Context, req *capv1.DescribeCapabilitiesRequest) (*capv1.DescribeCapabilitiesResponse, error) {
    descriptors := s.registry.List()
    
    // 计算 catalog digest
    digest := computeCatalogDigest(descriptors)
    
    return &capv1.DescribeCapabilitiesResponse{
        Capabilities:   descriptors,
        CatalogVersion: 1,
        CatalogDigest:  digest,
    }, nil
}

func computeCatalogDigest(descriptors []*capv1.CapabilityDescriptor) []byte {
    h := sha256.New()
    for _, desc := range descriptors {
        h.Write([]byte(desc.CapabilityId))
        h.Write([]byte(desc.SemanticVersion))
    }
    return h.Sum(nil)
}
```

## 3. ✅ 实现 Query Handler

**文件**: `internal/capability/server/handlers.go`
**问题**: 返回 Unimplemented

**修复**:
```go
func (s *Server) Query(ctx context.Context, req *capv1.QueryRequest) (*capv1.QueryResponse, error) {
    if err := s.acquireQuerySem(ctx); err != nil {
        return nil, err
    }
    defer s.releaseQuerySem()

    // 验证 capability 存在
    cap, ok := s.registry.Get(req.CapabilityId)
    if !ok {
        return &capv1.QueryResponse{
            Error: &capv1.CapabilityError{
                Code:    capv1.ErrorCode_ERROR_CODE_NOT_FOUND,
                Message: "capability not found",
            },
        }, nil
    }

    // 执行 query
    result, err := cap.HandleOperation(ctx, req.Operation, req.RequestJson)
    if err != nil {
        return &capv1.QueryResponse{
            Error: &capv1.CapabilityError{
                Code:    capv1.ErrorCode_ERROR_CODE_INTERNAL,
                Message: err.Error(),
            },
        }, nil
    }

    return &capv1.QueryResponse{
        ResponseJson: result,
    }, nil
}
```

## 4. ✅ 实现 IntegrateWithServer

**文件**: `internal/agentcapability/registry.go`
**问题**: TODO 未实现

**修复**:
```go
func (r *Registry) IntegrateWithServer(s *server.Server) {
    s.SetRegistry(r)
}
```

**同时在 Server 添加**:
```go
func (s *Server) SetRegistry(registry *Registry) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.registry = registry
    s.ready = true
}
```

## 5. ✅ 添加基本的 Echo Capability (测试用)

**文件**: `internal/agentcapability/echo/capability.go`
**目的**: 有一个完整可测试的 capability

**实现**:
```go
package echo

import (
    "context"
    "encoding/json"
    capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

type Capability struct{}

func NewCapability() *Capability {
    return &Capability{}
}

func (c *Capability) Descriptor() *capv1.CapabilityDescriptor {
    return &capv1.CapabilityDescriptor{
        CapabilityId:    "agent.echo.v1",
        SemanticVersion: "1.0.0",
        ProtocolVersion: 1,
        DisplayName:     "Echo",
        Description:     "Echo test capability",
        Readiness:       true,
        Operations: []*capv1.OperationDescriptor{
            {
                OperationId:   "echo",
                DisplayName:   "Echo",
                OperationType: capv1.OperationType_OPERATION_TYPE_READ,
                Audience:      []capv1.Audience{capv1.Audience_AUDIENCE_UNSPECIFIED},
                RiskLevel:     capv1.RiskLevel_RISK_LEVEL_SAFE,
            },
        },
    }
}

func (c *Capability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
    var input map[string]interface{}
    json.Unmarshal(inputJSON, &input)
    
    output := map[string]interface{}{
        "echo": input,
        "timestamp": time.Now().Unix(),
    }
    
    return json.Marshal(output)
}
```

---

## 实施步骤

1. 修复 Server 结构
2. 实现 handlers
3. 添加 Echo capability
4. 集成测试
5. 验证端到端流程

---

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
