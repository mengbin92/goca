// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v5.27.1
// source: goca/v1/cert.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	Cert_GenKey_FullMethodName     = "/goca.v1.Cert/GenKey"
	Cert_CSR_FullMethodName        = "/goca.v1.Cert/CSR"
	Cert_GetCert_FullMethodName    = "/goca.v1.Cert/GetCert"
	Cert_CASignCSR_FullMethodName  = "/goca.v1.Cert/CASignCSR"
	Cert_RevokeCert_FullMethodName = "/goca.v1.Cert/RevokeCert"
	Cert_PKCS12_FullMethodName     = "/goca.v1.Cert/PKCS12"
)

// CertClient is the client API for Cert service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CertClient interface {
	GenKey(ctx context.Context, in *GenKeyRequest, opts ...grpc.CallOption) (*GenKeyResponse, error)
	CSR(ctx context.Context, in *CSRRequest, opts ...grpc.CallOption) (*CSRResponse, error)
	GetCert(ctx context.Context, in *CertRequest, opts ...grpc.CallOption) (*CertResponse, error)
	CASignCSR(ctx context.Context, in *CASignCSRRequest, opts ...grpc.CallOption) (*CASignCSRResponse, error)
	RevokeCert(ctx context.Context, in *RevokeCertRequest, opts ...grpc.CallOption) (*RevokeCertResponse, error)
	PKCS12(ctx context.Context, in *PKCS12Request, opts ...grpc.CallOption) (*PKCS12Response, error)
}

type certClient struct {
	cc grpc.ClientConnInterface
}

func NewCertClient(cc grpc.ClientConnInterface) CertClient {
	return &certClient{cc}
}

func (c *certClient) GenKey(ctx context.Context, in *GenKeyRequest, opts ...grpc.CallOption) (*GenKeyResponse, error) {
	out := new(GenKeyResponse)
	err := c.cc.Invoke(ctx, Cert_GenKey_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *certClient) CSR(ctx context.Context, in *CSRRequest, opts ...grpc.CallOption) (*CSRResponse, error) {
	out := new(CSRResponse)
	err := c.cc.Invoke(ctx, Cert_CSR_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *certClient) GetCert(ctx context.Context, in *CertRequest, opts ...grpc.CallOption) (*CertResponse, error) {
	out := new(CertResponse)
	err := c.cc.Invoke(ctx, Cert_GetCert_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *certClient) CASignCSR(ctx context.Context, in *CASignCSRRequest, opts ...grpc.CallOption) (*CASignCSRResponse, error) {
	out := new(CASignCSRResponse)
	err := c.cc.Invoke(ctx, Cert_CASignCSR_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *certClient) RevokeCert(ctx context.Context, in *RevokeCertRequest, opts ...grpc.CallOption) (*RevokeCertResponse, error) {
	out := new(RevokeCertResponse)
	err := c.cc.Invoke(ctx, Cert_RevokeCert_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *certClient) PKCS12(ctx context.Context, in *PKCS12Request, opts ...grpc.CallOption) (*PKCS12Response, error) {
	out := new(PKCS12Response)
	err := c.cc.Invoke(ctx, Cert_PKCS12_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CertServer is the server API for Cert service.
// All implementations must embed UnimplementedCertServer
// for forward compatibility
type CertServer interface {
	GenKey(context.Context, *GenKeyRequest) (*GenKeyResponse, error)
	CSR(context.Context, *CSRRequest) (*CSRResponse, error)
	GetCert(context.Context, *CertRequest) (*CertResponse, error)
	CASignCSR(context.Context, *CASignCSRRequest) (*CASignCSRResponse, error)
	RevokeCert(context.Context, *RevokeCertRequest) (*RevokeCertResponse, error)
	PKCS12(context.Context, *PKCS12Request) (*PKCS12Response, error)
	mustEmbedUnimplementedCertServer()
}

// UnimplementedCertServer must be embedded to have forward compatible implementations.
type UnimplementedCertServer struct {
}

func (UnimplementedCertServer) GenKey(context.Context, *GenKeyRequest) (*GenKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenKey not implemented")
}
func (UnimplementedCertServer) CSR(context.Context, *CSRRequest) (*CSRResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CSR not implemented")
}
func (UnimplementedCertServer) GetCert(context.Context, *CertRequest) (*CertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCert not implemented")
}
func (UnimplementedCertServer) CASignCSR(context.Context, *CASignCSRRequest) (*CASignCSRResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CASignCSR not implemented")
}
func (UnimplementedCertServer) RevokeCert(context.Context, *RevokeCertRequest) (*RevokeCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RevokeCert not implemented")
}
func (UnimplementedCertServer) PKCS12(context.Context, *PKCS12Request) (*PKCS12Response, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PKCS12 not implemented")
}
func (UnimplementedCertServer) mustEmbedUnimplementedCertServer() {}

// UnsafeCertServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CertServer will
// result in compilation errors.
type UnsafeCertServer interface {
	mustEmbedUnimplementedCertServer()
}

func RegisterCertServer(s grpc.ServiceRegistrar, srv CertServer) {
	s.RegisterService(&Cert_ServiceDesc, srv)
}

func _Cert_GenKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertServer).GenKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Cert_GenKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertServer).GenKey(ctx, req.(*GenKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cert_CSR_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CSRRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertServer).CSR(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Cert_CSR_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertServer).CSR(ctx, req.(*CSRRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cert_GetCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertServer).GetCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Cert_GetCert_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertServer).GetCert(ctx, req.(*CertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cert_CASignCSR_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CASignCSRRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertServer).CASignCSR(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Cert_CASignCSR_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertServer).CASignCSR(ctx, req.(*CASignCSRRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cert_RevokeCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RevokeCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertServer).RevokeCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Cert_RevokeCert_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertServer).RevokeCert(ctx, req.(*RevokeCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Cert_PKCS12_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PKCS12Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertServer).PKCS12(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Cert_PKCS12_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertServer).PKCS12(ctx, req.(*PKCS12Request))
	}
	return interceptor(ctx, in, info, handler)
}

// Cert_ServiceDesc is the grpc.ServiceDesc for Cert service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Cert_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "goca.v1.Cert",
	HandlerType: (*CertServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GenKey",
			Handler:    _Cert_GenKey_Handler,
		},
		{
			MethodName: "CSR",
			Handler:    _Cert_CSR_Handler,
		},
		{
			MethodName: "GetCert",
			Handler:    _Cert_GetCert_Handler,
		},
		{
			MethodName: "CASignCSR",
			Handler:    _Cert_CASignCSR_Handler,
		},
		{
			MethodName: "RevokeCert",
			Handler:    _Cert_RevokeCert_Handler,
		},
		{
			MethodName: "PKCS12",
			Handler:    _Cert_PKCS12_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "goca/v1/cert.proto",
}
