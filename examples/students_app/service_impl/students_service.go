package studentsservice

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strings"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sspb "grpcrestserver/examples/students_app/proto/students_service"
)

type StudentsRPCServiceImpl struct {
	R *rand.Rand
	l map[uint64]*sspb.Student
}

func (s *StudentsRPCServiceImpl) CreateStudent(ctx context.Context, in *sspb.Student) (*sspb.Student, error) {
	log.Printf("Create new student %v", in)
	student := proto.Clone(in).(*sspb.Student)
	student.Id = s.R.Uint64()
	if s.l == nil {
		s.l = map[uint64]*sspb.Student{}
	}
	s.l[student.Id] = student
	return student, nil
}

func (s *StudentsRPCServiceImpl) GetStudents(ctx context.Context, in *sspb.GetStudentMessage) (*sspb.Students, error) {
	log.Printf("User creds : %v", ctx.Value("creds"))
	log.Printf("Getting all the students with %v", in)
	students := []*sspb.Student{}
	for _, v := range s.l {
		if matchGet(in, v) {
			students = append(students, v)
		}
	}
	return &sspb.Students{
		Students: students,
	}, nil
}

func (s *StudentsRPCServiceImpl) GetStudent(ctx context.Context, in *sspb.GetStudentMessage) (*sspb.Student, error) {
	if student, ok := s.l[in.StudentId]; ok {
		return student, nil
	}
	return nil, status.Error(codes.NotFound, fmt.Sprintf("%v not found", in.StudentId))
}

func (s *StudentsRPCServiceImpl) UpdateStudent(ctx context.Context, in *sspb.Student) (*sspb.Student, error) {
	student, ok := s.l[in.Id]
	if !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprint("%v not found", in.Id))
	}
	s.l[in.Id] = patchStudent(student, in)
	return s.l[in.Id], nil
}

func (s *StudentsRPCServiceImpl) ReplaceStudent(ctx context.Context, in *sspb.Student) (*sspb.Student, error) {
	if _, ok := s.l[in.Id]; !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprint("%v not found", in.Id))
	}
	student := proto.Clone(in).(*sspb.Student)
	s.l[in.Id] = student
	return student, nil
}

func (s *StudentsRPCServiceImpl) DeleteStudent(ctx context.Context, in *sspb.Student) (*sspb.Empty, error) {
	if _, ok := s.l[in.Id]; !ok {
		return nil, status.Error(codes.NotFound, fmt.Sprint("%v not found", in.Id))
	}
	delete(s.l, in.Id)
	return &sspb.Empty{}, nil
}

// matchGet compares only if the field is set.
func matchGet(in *sspb.GetStudentMessage, st *sspb.Student) bool {
	m := true
	if in.FirstName != "" {
		m = m && strings.Contains(st.FirstName, in.FirstName)
	}
	if in.LastName != "" {
		m = m && strings.Contains(st.LastName, in.LastName)
	}
	if in.MaxAge != 0 {
		m = m && st.Age >= in.MinAge && st.Age <= in.MaxAge
	}
	if in.MotherName != "" {
		m = m && strings.Contains(st.MotherName, in.MotherName)
	}
	if in.FatherName != "" {
		m = m && strings.Contains(st.FatherName, in.FatherName)
	}
	return m
}

func patchStudent(st *sspb.Student, patch *sspb.Student) *sspb.Student {
	newSt := proto.Clone(st).(*sspb.Student)
	if patch.FirstName != "" {
		newSt.FirstName = patch.FirstName
	}
	if patch.LastName != "" {
		newSt.LastName = patch.LastName
	}
	if patch.Age != 0 {
		newSt.Age = patch.Age
	}
	if patch.MotherName != "" {
		newSt.MotherName = patch.MotherName
	}
	if patch.FatherName != "" {
		newSt.FatherName = patch.FatherName
	}
	return newSt
}
