package studentsservice

import (
	"context"
	"log"
	"math/rand"

	"github.com/golang/protobuf/proto"

	sspb "grpcrestserver/examples/students_app/proto/students_service"
)

type StudentsRPCServiceImpl struct {
	R *rand.Rand
	l []*sspb.Student
}

func (s *StudentsRPCServiceImpl) CreateStudent(ctx context.Context, in *sspb.Student) (*sspb.Student, error) {
	log.Printf("Create new student %v", in)
	student := proto.Clone(in).(*sspb.Student)
	student.Id = s.R.Uint64()
	if s.l == nil {
		s.l = make([]*sspb.Student, 0)
	}
	s.l = append(s.l, student)
	return student, nil
}

func (s *StudentsRPCServiceImpl) GetStudents(ctx context.Context, in *sspb.Empty) (*sspb.Students, error) {
	log.Printf("Getting all the students...")
	return &sspb.Students{
		Students: s.l,
	}, nil
}
