package serverconn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2instanceconnect"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
)

type ServerConn struct {
	logger    *zap.Logger
	role      string
	port      int
	sshClient *ssh.Client
	l         sync.Mutex
}

func New(logger *zap.Logger, role string, port int) (*ServerConn, error) {
	return &ServerConn{
		logger: logger,
		role:   role,
		port:   port,
		l:      sync.Mutex{},
	}, nil
}

func (s *ServerConn) Run(ctx context.Context) {
	address := fmt.Sprintf("127.0.0.1:%d", s.port)
	ln, err := net.Listen("tcp", address)
	if err != nil {
		s.logger.Error("error creating tcp listener",
			zap.String("address", address),
			zap.Error(err),
		)
		return
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.logger.Error("listening socket error",
				zap.String("role", s.role),
				zap.Int("port", s.port),
				zap.Error(err),
			)
			return
		}
		go s.HandleConn(conn, fmt.Sprintf("127.0.0.1:%d", s.port))
	}
}

func (s *ServerConn) SshClient() (*ssh.Client, error) {
	s.l.Lock()
	defer s.l.Unlock()
	if s.sshClient != nil {
		return s.sshClient, nil
	}
	svc, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Region: aws.String("us-east-2")},
	})
	if err != nil {

	}
	ec2svc := ec2.New(svc)
	input := ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:project"),
				Values: []*string{aws.String("novacloud-testing")},
			},
			{
				Name:   aws.String("tag:role"),
				Values: []*string{aws.String(s.role)},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []*string{aws.String("running")},
			},
		},
	}
	output, err := ec2svc.DescribeInstancesWithContext(context.TODO(), &input)
	if err != nil {
		s.logger.DPanic("error describing instances", zap.Error(err))
	}
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			client, err := sshIntoInstance(s.logger, svc, instance)
			if err != nil {
				s.logger.DPanic("failed to ssh into instance", zap.Error(err))
				return nil, err
			}
			s.sshClient = client
			return s.sshClient, nil
		}
	}
	return nil, errors.New("failed to ssh into anything")

}

func (s *ServerConn) HandleConn(conn net.Conn, address string) {
	client, err := s.SshClient()
	if err != nil {
		s.logger.DPanic("error getting ssh client", zap.Error(err))
		return
	}
	sshConn, err := client.Dial("tcp", address)
	if err != nil {
		s.l.Lock()
		defer s.l.Unlock()
		return
	}
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		io.Copy(conn, sshConn)
		conn.Close()
		wg.Done()
	}()
	go func() {
		io.Copy(sshConn, conn)
		sshConn.Close()
		wg.Done()
	}()
	wg.Wait()
}

func sshIntoInstance(logger *zap.Logger, sess *session.Session, instance *ec2.Instance) (*ssh.Client, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	ec2InstanceConnectSvc := ec2instanceconnect.New(sess)
	input := ec2instanceconnect.SendSSHPublicKeyInput{
		AvailabilityZone: instance.Placement.AvailabilityZone,
		InstanceId:       instance.InstanceId,
		InstanceOSUser:   aws.String("ec2-user"),
		SSHPublicKey:     aws.String(string(pubKeyBytes)),
	}
	_, err = ec2InstanceConnectSvc.SendSSHPublicKeyWithContext(context.TODO(), &input)
	if err != nil {
		logger.Error("failed to send ssh public key", zap.Error(err))
		return nil, err
	}
	logger.Info("sent ssh public key", zap.String("ip_address", *instance.PublicIpAddress))

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	clientConfig := ssh.ClientConfig{
		Config: ssh.Config{},
		User:   "ec2-user",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		BannerCallback:    nil,
		ClientVersion:     "",
		HostKeyAlgorithms: nil,
		Timeout:           0,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", *instance.PublicIpAddress), &clientConfig)
	if err != nil {
		return nil, err
	}
	return client, nil
}