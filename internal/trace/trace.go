// Package trace defines the run trace (schema v0) and writes it to disk as
// traces/<run_id>.json. A trace records everything the harness did in one
// run, so a PASS or FAIL can be checked afterward.
package trace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/tushar-patel28/agent-proving-ground/internal/sandbox"
)

// SchemaVersion is written into every trace so readers know the format.
const SchemaVersion = 0

// ExitReason says why a run stopped. It is its own type (a string
// underneath), so a function that takes an ExitReason cannot be handed
// any other string by mistake. The values are the fixed list from
// PLAN.md T2.2.
//
// check_passed / check_failed: the agent loop ended on its own (the model
// stopped calling tools, refused, or hit the per-reply max_tokens), and
// the check decided. The other reasons say which limit stopped the loop;
// the check still ran (except after error), and the verdict is its result.
type ExitReason string

const (
	ReasonCheckPassed          ExitReason = "check_passed"
	ReasonCheckFailed          ExitReason = "check_failed"
	ReasonBudgetSteps          ExitReason = "budget_steps"
	ReasonBudgetTokens         ExitReason = "budget_tokens"
	ReasonBudgetCost           ExitReason = "budget_cost"
	ReasonTimeout              ExitReason = "timeout"
	ReasonPolicyViolationLimit ExitReason = "policy_violation_limit"
	ReasonGateRefused          ExitReason = "gate_refused"  // reserved for the human gate (T2.4); not used yet
	ReasonGateDeferred         ExitReason = "gate_deferred" // reserved for the human gate (T2.4); not used yet
	ReasonError                ExitReason = "error"         // the harness failed; the check did not run
)

// Verdicts. Only the harness-run check produces PASS (D11).
const (
	VerdictPass = "PASS"
	VerdictFail = "FAIL"
)

// validReasons is a set: map keys are the members, struct{} takes no memory.
var validReasons = map[ExitReason]struct{}{
	ReasonCheckPassed: {}, ReasonCheckFailed: {}, ReasonBudgetSteps: {},
	ReasonBudgetTokens: {}, ReasonBudgetCost: {}, ReasonTimeout: {},
	ReasonPolicyViolationLimit: {}, ReasonGateRefused: {}, ReasonGateDeferred: {},
	ReasonError: {},
}

// ValidExitReason reports whether s is on the fixed list. It takes a plain
// string so it can check values read from a file.
func ValidExitReason(s string) bool {
	_, ok := validReasons[ExitReason(s)] // ok is true when the key exists
	return ok
}

// Trace is one run. The `json:"..."` tags set the field names in the file.
type Trace struct {
	SchemaVersion int        `json:"schema_version"`
	RunID         string     `json:"run_id"`
	TaskID        string     `json:"task_id"` // e.g. "001-fix-function"
	Pod           string     `json:"pod"`
	StartedAt     time.Time  `json:"started_at"` // time.Time encodes as RFC 3339
	EndedAt       time.Time  `json:"ended_at"`
	Commands      []Command  `json:"commands"`        // every host command, in order
	Steps         []Step     `json:"steps"`           // agent steps; empty without an agent
	ExitReason    ExitReason `json:"exit_reason"`     // why the run stopped
	Verdict       string     `json:"verdict"`         // PASS or FAIL: the check's result
	Check         Check      `json:"check"`           // the check that decided the verdict
	CheckRuns     []CheckRun `json:"check_runs"`      // every time the check ran (T2.3), in order
	Error         string     `json:"error,omitempty"` // harness error; omitempty drops it when ""

	// Agent fields. omitempty leaves them out of --no-agent traces.
	Model             string  `json:"model,omitempty"`
	LoopStop          string  `json:"loop_stop,omitempty"` // why the agent loop ended: end_turn | max_steps | max_tokens | refusal
	TotalInputTokens  int64   `json:"total_input_tokens,omitempty"`
	TotalOutputTokens int64   `json:"total_output_tokens,omitempty"`
	EstimatedCostUSD  float64 `json:"estimated_cost_usd,omitempty"` // from list prices; not a bill
	Budget            *Budget `json:"budget,omitempty"`             // pointer: nil (omitted) without an agent
}

// Check is the hidden check's outcome. It runs after every exit except
// error.
type Check struct {
	Ran      bool `json:"ran"`
	ExitCode *int `json:"exit_code,omitempty"` // nil when it did not run; 0 means PASS
}

// CheckRun is one run of the hidden check. Its output stays in the
// commands (phase check); the model never sees it.
type CheckRun struct {
	AfterStep        int    `json:"after_step"` // the step that changed /workspace; 0 for the final check
	Trigger          string `json:"trigger"`    // workspace_changed | final
	ExitCode         int    `json:"exit_code"`
	Passed           bool   `json:"passed"`
	Killed           int    `json:"killed"`            // processes killed before the check ran
	WorkspaceSHA256  string `json:"workspace_sha256"`  // fingerprint of /workspace the check saw
	ChangedWorkspace bool   `json:"changed_workspace"` // the check run itself changed /workspace (see internal/stop)
}

// Check triggers, used in CheckRun.Trigger.
const (
	TriggerWorkspaceChanged = "workspace_changed" // a step changed /workspace
	TriggerFinal            = "final"             // the agent loop ended
)

// Budget is the run's limits and what it used (T2.2).
type Budget struct {
	Limits       BudgetLimits `json:"limits"`
	FromContract []string     `json:"from_contract"` // the limits the contract set; the others are harness defaults
	Used         BudgetUsed   `json:"used"`
}

// BudgetLimits mirrors budget.Limits, with JSON names.
type BudgetLimits struct {
	MaxSteps            int     `json:"max_steps"`
	MaxTotalTokens      int64   `json:"max_total_tokens"`
	MaxCostUSD          float64 `json:"max_cost_usd"`
	TimeoutSeconds      float64 `json:"timeout_seconds"`
	MaxPolicyViolations int     `json:"max_policy_violations"`
	MaxReplyTokens      int64   `json:"max_reply_tokens"` // per model reply; the worst case each pre-call check assumes
}

// BudgetUsed is what the agent loop spent.
type BudgetUsed struct {
	Steps            int     `json:"steps"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	AgentSeconds     float64 `json:"agent_seconds"` // wall-clock time of the agent loop
	PolicyViolations int     `json:"policy_violations"`
	CountTokensCalls int     `json:"count_tokens_calls"` // pre-call token counts (free API calls, not in the totals)
}

// Command is one host command the sandbox ran, tagged with the run phase.
type Command struct {
	Phase string `json:"phase"` // start | setup | agent | check | stop

	// Embedded struct (a type with no field name): its fields (args,
	// stdout, stderr, exit_code) appear directly in this JSON object.
	sandbox.Result
}

// Step is one agent step: one model turn and the (at most one) tool call
// it made.
type Step struct {
	N          int    `json:"n"` // 1-based
	StopReason string `json:"stop_reason"`
	Text       string `json:"text,omitempty"`      // the model's text in this turn, truncated
	Tool       string `json:"tool,omitempty"`      // empty when the turn made no tool call
	Input      string `json:"input,omitempty"`     // tool input as raw JSON text, truncated
	Output     string `json:"output,omitempty"`    // tool result sent back to the model, truncated
	ExitCode   *int   `json:"exit_code,omitempty"` // pointer: nil (omitted) when nothing ran in the sandbox
	IsError    bool   `json:"is_error,omitempty"`
	Verdict    string `json:"verdict,omitempty"` // policy decision on the tool call: allowed | denied; empty when no tool call
	Rule       string `json:"rule,omitempty"`    // the policy rule that denied it (internal/policy Rule* constants)
	Reason     string `json:"reason,omitempty"`  // why it was denied; the same text the model was sent

	WorkspaceChanged bool  `json:"workspace_changed,omitempty"` // the step changed /workspace, so the check ran
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"` // includes thinking tokens
}

// Policy verdicts on a step's tool call, used in Step.Verdict. A denied
// call was never executed.
const (
	StepAllowed = "allowed"
	StepDenied  = "denied"
)

// Phases of a run, used in Command.Phase.
const (
	PhaseStart = "start"
	PhaseSetup = "setup"
	PhaseAgent = "agent" // commands run by the agent's tool calls

	PhaseFingerprint = "fingerprint" // the harness hashing /workspace after a step
	PhaseCheck       = "check"
	PhaseStop        = "stop"
)

// NewRunID returns a sortable, file-name-safe run ID: UTC time plus a
// suffix, e.g. "20261112T050102Z-1a2b3c4d".
func NewRunID(now time.Time, suffix string) string {
	// Go time layouts are written using the reference date
	// Mon Jan 2 15:04:05 2006; each part shows where that field goes.
	return now.UTC().Format("20060102T150405Z") + "-" + suffix
}

// runIDPattern allows letters, digits, "_" and "-" only, so a run ID can
// never contain "/" or ".." and escape the traces directory.
var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Validate checks the fields a reader relies on.
func (t *Trace) Validate() error {
	// errors.Join returns nil if every error is nil, or one error listing all.
	var errs []error
	if t.SchemaVersion != SchemaVersion {
		errs = append(errs, fmt.Errorf("schema_version %d, want %d", t.SchemaVersion, SchemaVersion))
	}
	if !runIDPattern.MatchString(t.RunID) {
		errs = append(errs, fmt.Errorf("run_id %q: only letters, digits, _ and - allowed", t.RunID))
	}
	if t.TaskID == "" {
		errs = append(errs, errors.New("task_id is empty"))
	}
	if !ValidExitReason(string(t.ExitReason)) {
		errs = append(errs, fmt.Errorf("exit_reason %q is not on the fixed list", t.ExitReason))
	}
	if t.Verdict != VerdictPass && t.Verdict != VerdictFail {
		errs = append(errs, fmt.Errorf("verdict %q, want PASS or FAIL", t.Verdict))
	}
	return errors.Join(errs...)
}

// Write validates t and writes it to dir/<run_id>.json. It never
// overwrites: if the file exists, it returns an error.
func Write(dir string, t *Trace) (string, error) {
	if err := t.Validate(); err != nil {
		return "", fmt.Errorf("invalid trace: %w", err)
	}
	// A nil slice encodes as null; an empty one as []. Readers get [].
	if t.Commands == nil {
		t.Commands = []Command{}
	}
	if t.Steps == nil {
		t.Steps = []Step{}
	}
	if t.CheckRuns == nil {
		t.CheckRuns = []CheckRun{}
	}
	// An Encoder (not json.Marshal) so HTML escaping can be turned off:
	// by default Go writes ">" as "\u003e", which makes pytest output in
	// traces hard to read. Encode also adds the final newline.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(t); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, t.RunID+".json")
	// O_EXCL with O_CREATE fails if the file already exists.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return "", err
	}
	return path, f.Close() // Close can report a failed write, so return its error
}
