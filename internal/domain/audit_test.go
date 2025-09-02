package domain

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestNewAuditFailure(t *testing.T) {
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	ctx := SignContext{Now: now, SourceIP: "1.2.3.4"}
	id := Identity{Subject: "sub"}
	ev := NewAuditFailure(ActionIssueUserCert, StagePolicy, id, []string{"alice"}, ctx, ErrPolicyDenied, map[string]string{"authz": "opa"})

	if ev.Action != ActionIssueUserCert || ev.Stage != StagePolicy {
		t.Fatalf("bad action/stage: %+v", ev)
	}
	if ev.Time != now || ev.SourceIP != "1.2.3.4" {
		t.Fatalf("bad time/ip: %+v", ev)
	}
	if ev.Subject != "sub" {
		t.Fatalf("bad identity: %+v", ev)
	}
	if ev.ErrorCode != CodePolicyDenied || ev.ErrorMessage == "" {
		t.Fatalf("bad error: %+v", ev)
	}
	if ev.Attrs["authz"] != "opa" {
		t.Fatalf("bad attrs: %+v", ev)
	}
	if ev.Serial != nil || ev.NotAfter != nil || ev.NotBefore != nil || ev.KeyFP != "" {
		t.Fatalf("unexpected success fields set: %+v", ev)
	}
}

func TestNewAuditSuccessAndSuccessMethod(t *testing.T) {
	now := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	ctx := SignContext{Now: now, SourceIP: "5.6.7.8"}
	id := Identity{Subject: "sub"}
	serial := uint64(99)
	nb := now.Add(-time.Minute)
	na := now.Add(time.Hour)
	ev := NewAuditSuccess(ActionIssueUserCert, id, []string{"alice"}, serial, nb, na, ctx, map[string]string{"signer": "sshca"})

	if !ev.Success() {
		t.Fatalf("expected success event")
	}
	if ev.Action != ActionIssueUserCert || ev.Stage != StageSign {
		t.Fatalf("bad action/stage: %+v", ev)
	}
	if ev.Time != now || ev.SourceIP != "5.6.7.8" {
		t.Fatalf("bad time/ip: %+v", ev)
	}
	if ev.Serial == nil || *ev.Serial != serial {
		t.Fatalf("bad serial: %+v", ev.Serial)
	}
	if ev.NotBefore == nil || *ev.NotBefore != nb || ev.NotAfter == nil || *ev.NotAfter != na {
		t.Fatalf("bad validity: nb=%v na=%v", ev.NotBefore, ev.NotAfter)
	}
	if ev.Attrs["signer"] != "sshca" {
		t.Fatalf("bad attrs: %+v", ev.Attrs)
	}
}
func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
		wantMsg  string
	}{
		{
			name:     "nil error",
			err:      nil,
			wantCode: "",
			wantMsg:  "",
		},
		{
			name:     "ErrMissingPublicKey",
			err:      ErrMissingPublicKey,
			wantCode: "MISSING_PUBLIC_KEY",
			wantMsg:  "missing public key",
		},
		{
			name:     "ErrNoPrincipals",
			err:      ErrNoPrincipals,
			wantCode: "NO_PRINCIPALS",
			wantMsg:  "no principals",
		},
		{
			name:     "ErrInvalidValidity",
			err:      ErrInvalidValidity,
			wantCode: "INVALID_VALIDITY",
			wantMsg:  "invalid validity window",
		},
		{
			name:     "ErrPolicyDenied",
			err:      ErrPolicyDenied,
			wantCode: "POLICY_DENIED",
			wantMsg:  "policy denied issuance",
		},
		{
			name:     "wrapped ErrPolicyDenied",
			err:      fmt.Errorf("wrap: %w", ErrPolicyDenied),
			wantCode: "POLICY_DENIED",
			wantMsg:  "policy denied issuance",
		},
		{
			name:     "PolicyDeny with message",
			err:      PolicyDeny{Code: DenyPrincipalNotAllowed, Message: "principal not allowed"},
			wantCode: "POLICY_DENIED",
			wantMsg:  "principal not allowed",
		},
		{
			name:     "PolicyDeny no message",
			err:      PolicyDeny{Code: DenyDefault},
			wantCode: "POLICY_DENIED",
			wantMsg:  "policy denied",
		},
		{
			name:     "unknown error",
			err:      errors.New("something else"),
			wantCode: "UNKNOWN_ERROR",
			wantMsg:  "unexpected error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, msg := ClassifyError(tt.err)
			if string(code) != tt.wantCode || msg != tt.wantMsg {
				t.Errorf("ClassifyError(%v) = (%q, %q), want (%q, %q)", tt.err, code, msg, tt.wantCode, tt.wantMsg)
			}
		})
	}
}

func TestAuditEventValidateAndTrace(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx := SignContext{Now: now, SourceIP: "1.1.1.1", TraceID: "trace-123"}
	id := Identity{Subject: "s"}
	serial := uint64(1)
	nb, na := now.Add(-time.Minute), now.Add(time.Hour)

	ok := NewAuditSuccess(ActionIssueUserCert, id, []string{"u"}, serial, nb, na, ctx, nil)
	if ok.TraceID != "trace-123" {
		t.Fatalf("trace id not propagated: %+v", ok)
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("success validate: %v", err)
	}

	fail := NewAuditFailure(ActionIssueUserCert, StagePolicy, id, nil, ctx, ErrPolicyDenied, nil)
	if err := fail.Validate(); err != nil {
		t.Fatalf("failure validate: %v", err)
	}
}

func TestAuditEventValidate_Errors(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	id := Identity{Subject: "s"}
	ctx := SignContext{Now: now}
	serial := uint64(7)
	nb, na := now.Add(-time.Minute), now.Add(time.Hour)

	// success missing serial
	ok := NewAuditSuccess(ActionIssueUserCert, id, []string{"u"}, serial, nb, na, ctx, nil)
	ok.Serial = nil
	if err := ok.Validate(); err == nil {
		t.Fatalf("want error for missing serial")
	}

	// success with error fields populated
	ok2 := NewAuditSuccess(ActionIssueUserCert, id, []string{"u"}, serial, nb, na, ctx, nil)
	ok2.ErrorCode = CodeUnknownError
	ok2.ErrorMessage = "oops"
	if err := ok2.Validate(); err == nil {
		t.Fatalf("want error for success with error fields")
	}

	// success with only error message populated
	ok3 := NewAuditSuccess(ActionIssueUserCert, id, []string{"u"}, serial, nb, na, ctx, nil)
	ok3.ErrorMessage = "oops"
	if err := ok3.Validate(); err == nil {
		t.Fatalf("want error for success with error message set")
	}

	// success with NotBefore missing (serial present)
	ok4 := NewAuditSuccess(ActionIssueUserCert, id, []string{"u"}, serial, nb, na, ctx, nil)
	ok4.NotBefore = nil
	if err := ok4.Validate(); err == nil {
		t.Fatalf("want error for success missing NotBefore")
	}

	// success with NotAfter missing (serial present)
	ok5 := NewAuditSuccess(ActionIssueUserCert, id, []string{"u"}, serial, nb, na, ctx, nil)
	ok5.NotAfter = nil
	if err := ok5.Validate(); err == nil {
		t.Fatalf("want error for success missing NotAfter")
	}

	// failure with success fields present
	fail := NewAuditFailure(ActionIssueUserCert, StagePolicy, id, nil, ctx, ErrPolicyDenied, nil)
	fail.Serial = &serial
	if err := fail.Validate(); err == nil {
		t.Fatalf("want error for failure with serial set")
	}

	// failure with key identifiers present
	fail3 := NewAuditFailure(ActionIssueUserCert, StagePolicy, id, nil, ctx, ErrPolicyDenied, nil)
	fail3.KeyID = "kid"
	fail3.KeyFP = "fp"
	if err := fail3.Validate(); err == nil {
		t.Fatalf("want error for failure with key identifiers set")
	}

	// failure with only KeyID set
	failKid := NewAuditFailure(ActionIssueUserCert, StagePolicy, id, nil, ctx, ErrPolicyDenied, nil)
	failKid.KeyID = "kid"
	if err := failKid.Validate(); err == nil {
		t.Fatalf("want error for failure with KeyID set")
	}

	// failure with only KeyFP set
	failKfp := NewAuditFailure(ActionIssueUserCert, StagePolicy, id, nil, ctx, ErrPolicyDenied, nil)
	failKfp.KeyFP = "fp"
	if err := failKfp.Validate(); err == nil {
		t.Fatalf("want error for failure with KeyFP set")
	}

	// failure with NotBefore set
	nb2 := now
	fail4 := NewAuditFailure(ActionIssueUserCert, StagePolicy, id, nil, ctx, ErrPolicyDenied, nil)
	fail4.NotBefore = &nb2
	if err := fail4.Validate(); err == nil {
		t.Fatalf("want error for failure with NotBefore set")
	}

	// failure with NotAfter set
	na2 := now
	fail5 := NewAuditFailure(ActionIssueUserCert, StagePolicy, id, nil, ctx, ErrPolicyDenied, nil)
	fail5.NotAfter = &na2
	if err := fail5.Validate(); err == nil {
		t.Fatalf("want error for failure with NotAfter set")
	}

	// failure with missing error code
	fail2 := NewAuditFailure(ActionIssueUserCert, StagePolicy, id, nil, ctx, ErrPolicyDenied, nil)
	fail2.ErrorCode = ""
	if err := fail2.Validate(); err == nil {
		t.Fatalf("want error for failure without error code")
	}
}

func TestAuditEvent_Validate_Success(t *testing.T) {
	now := time.Now().UTC()
	serial := uint64(123)
	nb := now.Add(-time.Hour)
	na := now.Add(time.Hour)
	ev := AuditEvent{
		Time:         now,
		Action:       ActionIssueUserCert,
		Stage:        StageSign,
		Serial:       &serial,
		NotBefore:    &nb,
		NotAfter:     &na,
		ErrorCode:    "",
		ErrorMessage: "",
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("expected valid success event, got error: %v", err)
	}
}

func TestAuditEvent_Validate_SuccessMissingFields(t *testing.T) {
	now := time.Now().UTC()
	ev := AuditEvent{
		Time:      now,
		Action:    ActionIssueUserCert,
		Stage:     StageSign,
		ErrorCode: "",
	}
	if err := ev.Validate(); err == nil {
		t.Errorf("expected error for missing serial/validity, got nil")
	}
}

func TestAuditEvent_Validate_SuccessWithErrorFields(t *testing.T) {
	now := time.Now().UTC()
	serial := uint64(1)
	nb := now.Add(-time.Minute)
	na := now.Add(time.Hour)
	ev := AuditEvent{
		Time:         now,
		Action:       ActionIssueUserCert,
		Stage:        StageSign,
		Serial:       &serial,
		NotBefore:    &nb,
		NotAfter:     &na,
		ErrorCode:    CodePolicyDenied,
		ErrorMessage: "should not be here",
	}
	if err := ev.Validate(); err == nil {
		t.Errorf("expected error for error fields in success event, got nil")
	}
}

func TestAuditEvent_Validate_Failure(t *testing.T) {
	now := time.Now().UTC()
	ev := AuditEvent{
		Time:         now,
		Action:       ActionIssueUserCert,
		Stage:        StagePolicy,
		ErrorCode:    CodePolicyDenied,
		ErrorMessage: "policy denied",
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("expected valid failure event, got error: %v", err)
	}
}

func TestAuditEvent_Validate_FailureWithSuccessFields(t *testing.T) {
	now := time.Now().UTC()
	serial := uint64(1)
	nb := now.Add(-time.Minute)
	na := now.Add(time.Hour)
	ev := AuditEvent{
		Time:         now,
		Action:       ActionIssueUserCert,
		Stage:        StagePolicy,
		ErrorCode:    CodePolicyDenied,
		ErrorMessage: "policy denied",
		Serial:       &serial,
		NotBefore:    &nb,
		NotAfter:     &na,
		KeyFP:        "fp",
		KeyID:        "kid",
	}
	if err := ev.Validate(); err == nil {
		t.Errorf("expected error for success-only fields in failure event, got nil")
	}
}

func TestAuditEvent_Validate_FailureMissingErrorCode(t *testing.T) {
	now := time.Now().UTC()
	ev := AuditEvent{
		Time:         now,
		Action:       ActionIssueUserCert,
		Stage:        StagePolicy,
		ErrorMessage: "policy denied",
	}
	if err := ev.Validate(); err == nil {
		t.Errorf("expected error for missing error code in failure event, got nil")
	}
}
