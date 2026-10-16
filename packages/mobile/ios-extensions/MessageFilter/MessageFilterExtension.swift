import IdentityLookup

/// Filters SMS/MMS from senders that are not in the user's contacts.
/// A message that scores as a likely scam is moved to the "Junk" tab of Messages.
///
/// Apple runs this extension in a sandbox with no network access, and the message text
/// never leaves the phone. Enable it in Settings > Messages > Unknown & Spam > SMS Filter.
final class MessageFilterExtension: ILMessageFilterExtension {}

extension MessageFilterExtension: ILMessageFilterQueryHandling {
    func handle(
        _ queryRequest: ILMessageFilterQueryRequest,
        context: ILMessageFilterExtensionContext,
        completion: @escaping (ILMessageFilterQueryResponse) -> Void
    ) {
        let response = ILMessageFilterQueryResponse()
        let body = queryRequest.messageBody ?? ""
        let verdict = ScamRules.evaluate(body)
        response.action = verdict.level == "HIGH" ? .junk : .none
        completion(response)
    }
}
