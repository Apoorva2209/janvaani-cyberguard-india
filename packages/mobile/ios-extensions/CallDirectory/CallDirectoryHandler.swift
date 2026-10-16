import CallKit
import Foundation

/// Labels incoming calls from numbers listed in `scam-numbers.txt` as "Suspected scam".
///
/// The list ships with the app and starts empty on purpose: JanVaani does not invent
/// scam numbers. Add verified numbers, one per line with the country code and no "+"
/// (for example 919876543210), then rebuild. Enable the extension in
/// Settings > Phone > Call Blocking & Identification.
final class CallDirectoryHandler: CXCallDirectoryProvider {
    private let label = "Suspected scam (JanVaani)"

    override func beginRequest(with context: CXCallDirectoryExtensionContext) {
        context.delegate = self
        // iOS requires entries in ascending order, without duplicates.
        for number in loadNumbers() {
            context.addIdentificationEntry(withNextSequentialPhoneNumber: number, label: label)
        }
        context.completeRequest()
    }

    private func loadNumbers() -> [CXCallDirectoryPhoneNumber] {
        guard
            let url = Bundle(for: CallDirectoryHandler.self).url(forResource: "scam-numbers", withExtension: "txt"),
            let text = try? String(contentsOf: url, encoding: .utf8)
        else { return [] }

        var seen = Set<Int64>()
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            if let value = Int64(trimmed), value > 0 { seen.insert(value) }
        }
        return seen.sorted()
    }
}

extension CallDirectoryHandler: CXCallDirectoryExtensionContextDelegate {
    func requestFailed(for extensionContext: CXCallDirectoryExtensionContext, withError error: Error) {
        // Nothing to clean up. iOS keeps the previous list if an update fails.
    }
}
