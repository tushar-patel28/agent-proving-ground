// Package loop is the minimal agent loop: send the task to Claude, run each
// tool call in the sandbox, send the result back, and repeat until the model
// stops calling tools or the step budget runs out.
//
// Every tool call goes through policy.Check before it runs (T2.1). A denied
// call is recorded as a step with verdict "denied" and is never executed;
// the model gets the reason as an error result.
//
// The loop never decides PASS or FAIL. After it ends, the harness runs the
// hidden check, and only the check decides (D11).
package loop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"github.com/tushar-patel28/agent-proving-ground/internal/policy"
	"github.com/tushar-patel28/agent-proving-ground/internal/sandbox"
	"github.com/tushar-patel28/agent-proving-ground/internal/trace"
)

// maxOutput caps each tool result (sent to the model and kept in the trace)
// and each step's text. 8 << 10 is 8 * 1024 = 8 KiB.
const maxOutput = 8 << 10

// Why the loop ended (trace field loop_stop).
const (
	StopEndTurn   = "end_turn"   // the model replied without a tool call
	StopMaxSteps  = "max_steps"  // the step budget ran out
	StopMaxTokens = "max_tokens" // a reply hit max_tokens; its tool call (if any) was not run
	StopRefusal   = "refusal"    // the model declined
)

// Client is the one model call the loop needs. The real one wraps the
// Anthropic SDK; tests pass a fake, so they need no API key or network.
type Client interface {
	New(ctx context.Context, params anthropic.MessageNewParams) (*anthropic.Message, error)
}

// anthropicClient adapts the SDK client to Client.
type anthropicClient struct{ c anthropic.Client }

func (a *anthropicClient) New(ctx context.Context, p anthropic.MessageNewParams) (*anthropic.Message, error) {
	return a.c.Messages.New(ctx, p)
}

// NewAnthropicClient returns the real client. anthropic.NewClient reads
// ANTHROPIC_API_KEY from the environment itself; this code never reads,
// prints, or stores the key, and the key is never sent into the pod.
func NewAnthropicClient() Client {
	return &anthropicClient{c: anthropic.NewClient(option.WithRequestTimeout(2 * time.Minute))}
}

// Config is what the loop needs from the task contract.
type Config struct {
	Model     string
	Goal      string
	Tools     []string // allowed_tools from contract.json
	MaxSteps  int      // max model turns
	MaxTokens int64    // per model reply
}

// Result is what the loop did, for the trace.
type Result struct {
	Steps        []trace.Step
	InputTokens  int64
	OutputTokens int64
	CostUSD      float64 // estimated from list prices
	Stop         string  // one of the Stop* constants
}

const systemPrompt = `You are a coding agent. You work inside an isolated Linux container with no network access. The task's repository is at /workspace, which is also the working directory. You can act only through the tools you are given, and file paths must be inside /workspace. Every tool call is checked by a permission policy before it runs; a denied call is not run, and its result says why. Your work is checked independently after you finish. When the task is complete, reply with a short summary and do not call a tool.`

// Run runs the loop. rec is called for every sandbox command a tool runs,
// so the trace holds every host command. On error, Result still holds the
// steps done so far.
func Run(ctx context.Context, client Client, sb sandbox.Sandbox, cfg Config, rec func(sandbox.Result)) (Result, error) {
	var res Result
	tools, err := buildTools(cfg.Tools)
	if err != nil {
		return res, err
	}
	pol := policy.New(cfg.Tools)
	resolve := resolver(sb, rec)
	if cfg.MaxSteps <= 0 {
		return res, errors.New("max_steps must be positive")
	}

	// messages is the whole conversation; each request resends all of it.
	messages := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(fmt.Sprintf(
			"Task: %s\n\nYou have at most %d turns.", cfg.Goal, cfg.MaxSteps))),
	}

	for n := 1; ; n++ {
		if n > cfg.MaxSteps {
			res.Stop = StopMaxSteps
			return res, nil
		}
		resp, err := client.New(ctx, anthropic.MessageNewParams{
			Model:     cfg.Model, // anthropic.Model is a string type, so a plain string works
			MaxTokens: cfg.MaxTokens,
			System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
			Messages:  messages,
			Tools:     tools,
			// At most one tool call per reply, so one step = one model turn
			// = one tool call, and per-step token counts are exact.
			ToolChoice: anthropic.ToolChoiceUnionParam{
				OfAuto: &anthropic.ToolChoiceAutoParam{DisableParallelToolUse: anthropic.Bool(true)},
			},
		})
		if err != nil {
			return res, fmt.Errorf("model call %d: %w", n, err)
		}
		in, out := resp.Usage.InputTokens, resp.Usage.OutputTokens
		res.InputTokens += in
		res.OutputTokens += out
		cost, err := EstimateCost(cfg.Model, in, out)
		if err != nil {
			return res, err
		}
		res.CostUSD += cost

		// The reply goes into the history before its tool results.
		// ToParam converts the response type into the request type.
		messages = append(messages, resp.ToParam())
		step := trace.Step{N: n, StopReason: string(resp.StopReason), InputTokens: in, OutputTokens: out}

		// A reply cut off by max_tokens may hold a half-written tool call,
		// and a refusal holds none to run: stop without running anything.
		if resp.StopReason == anthropic.StopReasonMaxTokens || resp.StopReason == anthropic.StopReasonRefusal {
			step.Text = truncate(replyText(resp))
			res.Steps = append(res.Steps, step)
			if resp.StopReason == anthropic.StopReasonRefusal {
				res.Stop = StopRefusal
			} else {
				res.Stop = StopMaxTokens
			}
			return res, nil
		}

		var results []anthropic.ContentBlockParamUnion
		for _, block := range resp.Content {
			// AsAny returns the concrete block type; the type switch picks it.
			tu, ok := block.AsAny().(anthropic.ToolUseBlock)
			if !ok {
				continue
			}
			if step.Tool != "" {
				// Parallel calls are disabled, but if one arrives anyway it
				// still needs a result: the API rejects a tool_use without one.
				results = append(results, anthropic.NewToolResultBlock(tu.ID,
					"error: only one tool call per turn; this call was not run", true))
				continue
			}
			step.Tool, step.Input = tu.Name, truncate(string(tu.Input))
			d, err := pol.Check(ctx, tu.Name, tu.Input, resolve)
			if err != nil {
				res.Steps = append(res.Steps, step)
				return res, fmt.Errorf("step %d %s: policy: %w", n, tu.Name, err)
			}
			if !d.Allowed {
				// Never executed. The model is told which rule and why.
				step.Verdict, step.Rule, step.Reason = trace.StepDenied, d.Rule, d.Reason
				step.Output, step.IsError = fmt.Sprintf("denied by policy (rule: %s): %s. The call was not run.", d.Rule, d.Reason), true
				results = append(results, anthropic.NewToolResultBlock(tu.ID, step.Output, true))
				continue
			}
			step.Verdict = trace.StepAllowed
			o, err := runTool(ctx, sb, d, tu.Name, tu.Input, rec)
			if err != nil {
				res.Steps = append(res.Steps, step)
				return res, fmt.Errorf("step %d %s: %w", n, tu.Name, err)
			}
			step.Output, step.ExitCode, step.IsError = o.text, o.exitCode, o.isError
			results = append(results, anthropic.NewToolResultBlock(tu.ID, o.text, o.isError))
		}
		step.Text = truncate(replyText(resp))
		res.Steps = append(res.Steps, step)

		if len(results) == 0 {
			res.Stop = StopEndTurn
			return res, nil
		}
		// Tool results go back as the next user message.
		messages = append(messages, anthropic.NewUserMessage(results...))
	}
}

// replyText joins the text blocks of a reply.
func replyText(resp *anthropic.Message) string {
	var parts []string
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// toolDefs are the tools the harness can run. A task gets only the ones
// its contract lists.
var toolDefs = map[string]anthropic.ToolParam{
	"read_file": {
		Name:        "read_file",
		Description: anthropic.String("Read a text file inside /workspace and return its contents."),
		InputSchema: schema(map[string]any{
			"path": map[string]any{"type": "string", "description": "Path inside /workspace, absolute or relative to it."},
		}, "path"),
		Strict: anthropic.Bool(true),
	},
	"write_file": {
		Name:        "write_file",
		Description: anthropic.String("Create or overwrite a text file inside /workspace with the given content. Parent directories are created."),
		InputSchema: schema(map[string]any{
			"path":    map[string]any{"type": "string", "description": "Path inside /workspace, absolute or relative to it."},
			"content": map[string]any{"type": "string", "description": "The full new file content."},
		}, "path", "content"),
		Strict: anthropic.Bool(true),
	},
	"run_command": {
		Name: "run_command",
		Description: anthropic.String("Run one program with arguments in /workspace (the working directory), with a 60-second limit. " +
			"There is no shell: argv is passed to the program as-is, so pipes, &&, cd, redirection, globs, and quotes do not work; make one call per program. " +
			"argv[0] must be one of: " + strings.Join(policy.Programs, ", ") + ". " +
			"Path arguments must be inside /workspace. Returns the exit code, stdout, and stderr."),
		InputSchema: schema(map[string]any{
			"argv": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": `Program and arguments, e.g. ["python", "-m", "pytest", "-q"].`,
			},
		}, "argv"),
		Strict: anthropic.Bool(true),
	},
}

// schema builds a JSON Schema object. "required ...string" collects the
// remaining arguments into a slice. ExtraFields adds keys the SDK struct
// has no field for; strict tools need additionalProperties: false.
func schema(props map[string]any, required ...string) anthropic.ToolInputSchemaParam {
	return anthropic.ToolInputSchemaParam{
		Properties:  props,
		Required:    required,
		ExtraFields: map[string]any{"additionalProperties": false},
	}
}

// buildTools returns the tool list for the request. An unknown name in
// the contract is an error, not silently skipped. (Which calls may run is
// the policy's job: rule 1 checks each call against the contract.)
func buildTools(names []string) ([]anthropic.ToolUnionParam, error) {
	if len(names) == 0 {
		return nil, errors.New("contract allows no tools")
	}
	var tools []anthropic.ToolUnionParam
	for _, name := range names {
		def, ok := toolDefs[name]
		if !ok {
			return nil, fmt.Errorf("contract lists unknown tool %q", name)
		}
		// The Tools slice holds a union type; OfTool marks this one as a
		// custom tool. &def is safe: def is a fresh copy each iteration.
		tools = append(tools, anthropic.ToolUnionParam{OfTool: &def})
	}
	return tools, nil
}

// resolver returns the policy's Resolver for this sandbox: it runs
// "realpath -m -- p1 p2 ..." in the pod (argv, no shell), which prints the
// real path of each, following symlinks (-m: the path need not exist yet).
// The command is recorded like any other. A non-zero exit or the wrong
// number of lines returns no paths, so the policy denies the call.
func resolver(sb sandbox.Sandbox, rec func(sandbox.Result)) policy.Resolver {
	return func(ctx context.Context, paths []string) ([]string, error) {
		// "--" stops realpath reading options, though these paths all
		// start with "/workspace" anyway.
		r, err := sb.Exec(ctx, append([]string{"realpath", "-m", "--"}, paths...)...)
		rec(r)
		if err != nil {
			return nil, err
		}
		if r.ExitCode != 0 {
			return nil, nil
		}
		// The policy denies control characters in paths, so one line per
		// path is safe to split on.
		out := strings.Split(strings.TrimSuffix(r.Stdout, "\n"), "\n")
		if len(out) != len(paths) {
			return nil, nil
		}
		return out, nil
	}
}

// toolOutput is what one tool call returns to the model.
type toolOutput struct {
	text     string
	exitCode *int // nil when nothing ran in the sandbox
	isError  bool
}

func toolError(format string, args ...any) toolOutput {
	return toolOutput{text: "error: " + fmt.Sprintf(format, args...), isError: true}
}

// runTool executes one tool call that the policy allowed, using the
// decision's clean path or argv. The returned error is only for harness
// failures (kubectl failed, context expired), which end the run.
func runTool(ctx context.Context, sb sandbox.Sandbox, d policy.Decision, name string, raw json.RawMessage, rec func(sandbox.Result)) (toolOutput, error) {
	switch name {
	case "read_file":
		r, err := sb.Exec(ctx, "cat", d.Path)
		rec(r)
		if err != nil {
			return toolOutput{}, err
		}
		code := r.ExitCode
		if code != 0 {
			return toolOutput{text: "error: " + cleanStderr(r.Stderr), exitCode: &code, isError: true}, nil
		}
		return toolOutput{text: truncate(r.Stdout), exitCode: &code}, nil

	case "write_file":
		var in struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal(raw, &in); err != nil { // the policy already parsed it once
			return toolError("invalid input: %v", err), nil
		}
		return writeFile(ctx, sb, d.Path, in.Content, rec)

	case "run_command":
		// No shell: the argv goes to kubectl exec as separate arguments.
		// timeout kills the command inside the pod after 60 seconds (exit 124).
		r, err := sb.Exec(ctx, append([]string{"timeout", "60"}, d.Argv...)...)
		rec(r)
		if err != nil {
			return toolOutput{}, err
		}
		code := r.ExitCode
		text := fmt.Sprintf("exit_code: %d\n--- stdout ---\n%s\n--- stderr ---\n%s", code, r.Stdout, cleanStderr(r.Stderr))
		// A non-zero exit is information for the model, not a tool error.
		return toolOutput{text: truncate(text), exitCode: &code}, nil
	}
	return toolError("tool %q has no implementation", name), nil
}

// writeFile copies content into the pod: host temp file, then kubectl cp.
func writeFile(ctx context.Context, sb sandbox.Sandbox, p, content string, rec func(sandbox.Result)) (toolOutput, error) {
	r, err := sb.Exec(ctx, "mkdir", "-p", path.Dir(p))
	rec(r)
	if err != nil {
		return toolOutput{}, err
	}
	if r.ExitCode != 0 {
		code := r.ExitCode
		return toolOutput{text: "error: " + cleanStderr(r.Stderr), exitCode: &code, isError: true}, nil
	}

	f, err := os.CreateTemp("", "apg-write-*")
	if err != nil {
		return toolOutput{}, err
	}
	defer os.Remove(f.Name()) // runs when writeFile returns
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return toolOutput{}, err
	}
	if err := f.Close(); err != nil {
		return toolOutput{}, err
	}
	// CreateTemp makes the file 0600; kubectl cp keeps the mode, so match a
	// normal source file instead.
	if err := os.Chmod(f.Name(), 0o644); err != nil {
		return toolOutput{}, err
	}
	r, err = sb.CopyIn(ctx, f.Name(), p)
	rec(r)
	if err != nil {
		// A failed copy (for example, the path is an existing directory)
		// is reported to the model; the harness carries on.
		code := r.ExitCode
		return toolOutput{text: "error: " + cleanStderr(r.Stderr), exitCode: &code, isError: true}, nil
	}
	code := 0
	return toolOutput{text: fmt.Sprintf("wrote %d bytes to %s", len(content), p), exitCode: &code}, nil
}

// cleanStderr drops kubectl's own "command terminated with exit code N"
// line, which is noise for the model (the exit code is reported anyway).
func cleanStderr(s string) string {
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "command terminated with exit code") {
			keep = append(keep, line)
		}
	}
	return truncate(strings.TrimRight(strings.Join(keep, "\n"), "\n"))
}

// truncate cuts s to maxOutput bytes without splitting a UTF-8 character
// and says how much was cut.
func truncate(s string) string {
	if len(s) <= maxOutput {
		return s
	}
	cut := maxOutput
	// RuneStart reports whether a byte begins a character; step back until
	// it does, so the cut never lands inside a multi-byte character.
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("\n...[truncated %d bytes]", len(s)-cut)
}

// price is USD per million tokens. Long-prompt rates apply when one
// request's input exceeds longOver tokens.
type price struct {
	in, out         float64
	inLong, outLong float64
	longOver        int64
}

// prices are list prices from the Claude API pricing table (cached Nov 3,
// 2026). The estimate ignores prompt caching (not used) and taxes; it is not
// a bill.
var prices = map[string]price{
	"claude-haiku-5-5": {in: 0.10, out: 0.50, inLong: 0.50, outLong: 2.50, longOver: 100_000},
}

// EstimateCost returns the estimated USD cost of one request.
func EstimateCost(model string, inputTokens, outputTokens int64) (float64, error) {
	p, ok := prices[model]
	if !ok {
		return 0, fmt.Errorf("no price for model %q", model)
	}
	in, out := p.in, p.out
	if inputTokens > p.longOver {
		in, out = p.inLong, p.outLong
	}
	return (float64(inputTokens)*in + float64(outputTokens)*out) / 1e6, nil
}
