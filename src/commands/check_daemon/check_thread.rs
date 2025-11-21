pub enum OutboundMessage {
    Stop,
    PromptResponse(String),
    TriggerNow,
}
