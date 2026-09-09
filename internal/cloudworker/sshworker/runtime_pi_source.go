package sshworker

// Pi v0.84.4 JSON events are consumed at the Worker boundary. Only closed
// activity categories and the terminal assistant answer leave this parser.
const remotePiSource = `
type runtimeActivity struct {
 Sequence uint64 ` + "`json:\"sequence\"`" + `
 Phase string ` + "`json:\"phase\"`" + `
}
type piEventWriter struct {
 taskID string
 pending []byte
 report reportWriter
 events []runtimeActivity
 sequence uint64
 failureCode string
 httpStatus int
 terminal bool
 invalid bool
}
func(p *piEventWriter) Write(body []byte)(int,error){
 n:=len(body)
 for len(body)>0 {
  end:=bytes.IndexByte(body,'\n'); if end<0 {end=len(body)}
  if len(p.pending)+end>4<<20 {p.invalid=true;p.pending=nil;return n,nil}
  p.pending=append(p.pending,body[:end]...)
  if end==len(body){break}
  p.consume(p.pending);p.pending=nil;body=body[end+1:]
 }
 return n,nil
}
func(p *piEventWriter)activity(phase string){
 if len(p.events)>0 && p.events[len(p.events)-1].Phase==phase{return}
 p.sequence++
 p.events=append(p.events,runtimeActivity{Sequence:p.sequence,Phase:phase})
 if len(p.events)>64 {p.events=p.events[len(p.events)-64:]}
 body,_:=json.Marshal(p.events)
 file,err:=os.CreateTemp(taskPath(p.taskID,""),".activity-*");if err!=nil{return}
 defer os.Remove(file.Name())
 _,err=file.Write(body);closeErr:=file.Close();if err==nil && closeErr==nil {_=os.Rename(file.Name(),taskPath(p.taskID,"activity.json"))}
}
var providerStatusPattern=regexp.MustCompile("(?i)^(?:error[: ]+)?(?:(?:http|status(?: code)?)[ :]+)?([45][0-9]{2})(?:[: ;]|$)")
func(p *piEventWriter)consume(raw []byte){
 if len(bytes.TrimSpace(raw))==0{return}
 var event struct {
  Type string ` + "`json:\"type\"`" + `
  ToolName string ` + "`json:\"toolName\"`" + `
  IsError bool ` + "`json:\"isError\"`" + `
  Update struct{ Type string ` + "`json:\"type\"`" + ` } ` + "`json:\"assistantMessageEvent\"`" + `
  Message json.RawMessage ` + "`json:\"message\"`" + `
 }
 if json.Unmarshal(raw,&event)!=nil {p.invalid=true;return}
 switch event.Type {
 case "turn_start":p.terminal=false;p.activity("worker_waiting_model")
 case "message_update":
  switch event.Update.Type {case "thinking_start","thinking_delta":p.activity("worker_thinking");case "text_start","text_delta":p.activity("worker_responding")}
 case "tool_execution_start":
  phase:="worker_running_tool"
  switch event.ToolName {case "read","ls","find":phase="worker_reading";case "edit","write":phase="worker_editing";case "bash":phase="worker_command";case "grep":phase="worker_searching";case "subagent":phase="worker_delegating"}
  p.activity(phase)
 case "tool_execution_end":if event.IsError {p.activity("worker_tool_failed")} else {p.activity("worker_tool_complete")}
 case "message_end":
  var header struct{Role string ` + "`json:\"role\"`" + `}
  if json.Unmarshal(event.Message,&header)!=nil {p.invalid=true;return}
  if header.Role!="assistant" {return}
  var message struct {
   StopReason string ` + "`json:\"stopReason\"`" + `
   ErrorMessage string ` + "`json:\"errorMessage\"`" + `
   Content []struct{Type string ` + "`json:\"type\"`" + `;Text string ` + "`json:\"text\"`" + `} ` + "`json:\"content\"`" + `
  }
  if json.Unmarshal(event.Message,&message)!=nil {p.invalid=true;return}
  p.report=reportWriter{};p.terminal=true;p.failureCode="";p.httpStatus=0
  if message.StopReason=="error" || message.StopReason=="aborted" {
   p.failureCode="provider_request_failed"
   if match:=providerStatusPattern.FindStringSubmatch(strings.TrimSpace(message.ErrorMessage));len(match)==2 {p.httpStatus,_=strconv.Atoi(match[1])}
   lower:=strings.ToLower(message.ErrorMessage)
   if p.httpStatus==0 {switch {case strings.Contains(lower,"context length"),strings.Contains(lower,"context window"):p.failureCode="model_context_limit";case strings.Contains(lower,"timed out"),strings.Contains(lower,"timeout"):p.failureCode="model_request_timeout";case strings.Contains(lower,"connection"),strings.Contains(lower,"fetch failed"),strings.Contains(lower,"upstream_http2_stream_error"),strings.Contains(lower,"http/2 stream"),strings.Contains(lower,"http2 stream"),strings.Contains(lower,"connection reset"),strings.Contains(lower,"unexpected eof"),strings.Contains(lower,"stream id")&&strings.Contains(lower,"received from peer"):p.failureCode="model_connection_failed"}}
   // This diagnostic text is already redacted, remains private, and is never
   // used as public progress or promoted directly into the final response.
   fmt.Fprintln(os.Stderr,message.ErrorMessage)
   p.activity("worker_model_failed");return
  }
  for _,part:=range message.Content {if part.Type=="toolCall" {p.terminal=false;return}}
  for _,part:=range message.Content {if part.Type=="text" {_,_=p.report.Write([]byte(part.Text+"\n"))}}
 }
}
func(p *piEventWriter)finish()error{
 if len(bytes.TrimSpace(p.pending))>0 {p.consume(p.pending);p.pending=nil}
 if p.failureCode!="" {return errors.New("Worker model request failed")}
 if p.invalid || !p.terminal {p.failureCode="worker_protocol_invalid";return errors.New("Worker event stream was incomplete or invalid")}
 return nil
}
`
